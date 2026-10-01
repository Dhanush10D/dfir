"""In-memory test doubles (no Docker)."""

from __future__ import annotations

import itertools
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.core.hashing import Readable
from app.repositories.vault import (
    READ_CHUNK,
    ObjectInfo,
    PutResult,
    RetentionInfo,
    VaultObjectMissingError,
)


@dataclass
class _Version:
    version_id: str
    data: bytearray
    retain_until: datetime | None


@dataclass
class FakeVault:
    """Versioned, Object-Lock-like in-memory vault.

    ``tamper_put`` adds a new version at a key (what an attacker with write access could do);
    ``corrupt`` flips bytes of an existing version in place (storage corruption / lock bypass).
    """

    bucket: str = "evidence"
    retention_days: int | None = 3650
    objects: dict[str, list[_Version]] = field(default_factory=dict)
    fail_after_bytes: int | None = None
    max_read_seen: int = 0
    _ids: Iterator[int] = field(default_factory=lambda: itertools.count(1))

    def _new_version(self, key: str, data: bytes) -> _Version:
        retain = (
            datetime.now(UTC) + timedelta(days=self.retention_days) if self.retention_days else None
        )
        version = _Version(f"v{next(self._ids)}-{uuid.uuid4().hex[:6]}", bytearray(data), retain)
        self.objects.setdefault(key, []).append(version)
        return version

    def put_stream(
        self, key: str, reader: Readable, part_size: int, content_type: str
    ) -> PutResult:
        buffer = bytearray()
        while True:
            chunk = reader.read(part_size)
            self.max_read_seen = max(self.max_read_seen, len(chunk))
            if not chunk:
                break
            buffer.extend(chunk)
            if self.fail_after_bytes is not None and len(buffer) >= self.fail_after_bytes:
                raise ConnectionError("simulated vault failure")
        version = self._new_version(key, bytes(buffer))
        return PutResult(version_id=version.version_id, etag=f"etag-{version.version_id}")

    def _get(self, key: str, version_id: str | None) -> _Version:
        versions = self.objects.get(key)
        if not versions:
            raise VaultObjectMissingError(key)
        if version_id is None:
            return versions[-1]
        for version in versions:
            if version.version_id == version_id:
                return version
        raise VaultObjectMissingError(key)

    def iter_object(
        self, key: str, version_id: str | None = None, chunk_size: int = READ_CHUNK
    ) -> Iterator[bytes]:
        data = bytes(self._get(key, version_id).data)
        for start in range(0, len(data), chunk_size):
            yield data[start : start + chunk_size]

    def stat(self, key: str, version_id: str | None = None) -> ObjectInfo:
        version = self._get(key, version_id)
        return ObjectInfo(size=len(version.data), version_id=version.version_id, etag=None)

    def retention(self, key: str, version_id: str | None = None) -> RetentionInfo | None:
        version = self._get(key, version_id)
        if version.retain_until is None:
            return None
        return RetentionInfo(mode="COMPLIANCE", retain_until=version.retain_until)

    # --- tampering helpers for tests ---------------------------------------------------------

    def tamper_put(self, key: str, data: bytes) -> str:
        return self._new_version(key, data).version_id

    def corrupt(self, key: str, version_id: str | None = None, offset: int = 0) -> None:
        version = self._get(key, version_id)
        version.data[offset] ^= 0xFF

    def delete_all(self, key: str) -> None:
        self.objects.pop(key, None)


@dataclass
class FakeArtifactStore:
    """In-memory artifacts bucket; tests overwrite ``objects[key]`` to simulate tampering."""

    bucket: str = "artifacts"
    objects: dict[str, bytes] = field(default_factory=dict)

    def put_bytes(self, key: str, data: bytes, content_type: str) -> None:
        self.objects[key] = bytes(data)

    def get_bytes(self, key: str, max_bytes: int = 256 * 1024 * 1024) -> bytes:
        from app.repositories.artifacts import ArtifactMissingError

        if key not in self.objects:
            raise ArtifactMissingError(key)
        return self.objects[key]


# ---------------------------------------------------------------------------------------------
# Phase 9: outbound network doubles (nothing here opens a socket)
# ---------------------------------------------------------------------------------------------


class FakeResolver:
    """Injectable DNS: ``{host: [addresses]}``; unknown hosts fail like a real lookup."""

    def __init__(self, table: dict[str, list[str]] | None = None) -> None:
        self.table = dict(table or {})
        self.calls: list[str] = []

    def __call__(self, host: str, port: int) -> list[str]:
        self.calls.append(host)
        if host not in self.table:
            raise OSError(f"unknown host {host}")
        return list(self.table[host])


class FakeTransport:
    """Records every prepared request; answers from ``responses`` (or ``default``)."""

    def __init__(self) -> None:
        from app.integrations.outbound import HttpResponse

        self.requests: list[object] = []
        self.responses: list[object] = []
        self.default: object = HttpResponse(200, {}, b"ok")

    def send(self, request: object) -> object:
        self.requests.append(request)
        item = self.responses.pop(0) if self.responses else self.default
        if isinstance(item, Exception):
            raise item
        return item


class FakeSmtpSession:
    """Stands in for smtplib.SMTP: records logins and messages."""

    def __init__(self, sink: list[dict[str, object]], server: object, ip: str) -> None:
        self.sink = sink
        self.server = server
        self.ip = ip
        self.logged_in: tuple[str, str] | None = None

    def login(self, user: str, password: str) -> None:
        self.logged_in = (user, password)

    def send_message(self, message: object, from_addr: str, to_addrs: list[str]) -> None:
        self.sink.append(
            {
                "message": message,
                "from": from_addr,
                "to": list(to_addrs),
                "ip": self.ip,
                "server": self.server,
                "login": self.logged_in,
            }
        )

    def quit(self) -> None:
        return None

    def close(self) -> None:
        return None

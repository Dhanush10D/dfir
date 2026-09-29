"""Triage bundle reader: hostile-archive checks, manifest verification, bounded extraction. Pure.

A bundle is a ZIP with ``manifest.json`` at the root (``dfirbench.triage/1``). It comes from a
possibly compromised host, so everything in it is untrusted:

* **Inspection** (central directory only, nothing extracted) refuses the whole bundle on any
  unsafe member name (absolute, drive letter, backslash, ``..``, control characters, ...), a
  symlink / reparse point / hard link / device (any non-regular, non-directory mode), encrypted
  members, compression other than stored/deflate, duplicate names (also case-insensitively),
  overlapping local headers (the "overlapping files" zip bomb), or when the member count, the
  declared sizes or the compression ratios exceed :class:`BundleLimits`.
* **Extraction** streams each member into ``dest/NNNNN.bin`` (a fixed name, never derived from the
  archive) with ``O_EXCL``, hashing and counting bytes as they are decompressed; the declared sizes
  are not trusted (the running total is enforced again while reading). The copies are made
  read-only.
* **Verification** compares every member with the manifest: ``verified`` only when the SHA-256
  and the size match; otherwise ``hash_mismatch``, ``size_mismatch``, ``corrupt`` (CRC/deflate
  error), ``unlisted`` (not in the manifest) or ``missing`` (listed, not in the archive). Only
  verified members may be ingested.

Nothing here touches the database or the network, and nothing is written outside ``dest``.
"""

from __future__ import annotations

import hashlib
import os
import stat
import unicodedata
import zipfile
import zlib
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any

from app.collection.manifest import (
    MAX_MANIFEST_BYTES,
    FileEntry,
    ManifestError,
    TriageManifest,
    parse_manifest,
)
from app.collection.names import unsafe_name_reason
from app.parsers.normalize import clean_text

MANIFEST_NAME = "manifest.json"
MIB = 1024 * 1024
READ_CHUNK = MIB
PROGRESS_EVERY = 64 * MIB
MAX_REASONS = 50
LOCAL_HEADER_MIN = 30  # fixed part of a ZIP local file header
ALLOWED_COMPRESSION = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
DOS_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT in the low external attribute bytes
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
GZIP_MAGIC = b"\x1f\x8b"

VERIFIED = "verified"
FLAGGED_STATUSES = frozenset({"hash_mismatch", "size_mismatch", "corrupt", "unlisted", "missing"})


@dataclass(frozen=True)
class BundleLimits:
    max_members: int = 10_000
    max_total_bytes: int = 4096 * MIB
    max_member_bytes: int = 2048 * MIB
    max_ratio: int = 200
    ratio_floor_bytes: int = MIB  # ratios are only judged above this size
    max_manifest_bytes: int = MAX_MANIFEST_BYTES

    def as_dict(self) -> dict[str, int]:
        return {
            "max_members": self.max_members,
            "max_total_bytes": self.max_total_bytes,
            "max_member_bytes": self.max_member_bytes,
            "max_ratio": self.max_ratio,
            "ratio_floor_bytes": self.ratio_floor_bytes,
            "max_manifest_bytes": self.max_manifest_bytes,
        }


class BundleRejectedError(Exception):
    """The bundle as a whole is refused (hostile or unusable); ``reasons`` explain why."""

    def __init__(self, reasons: list[dict[str, Any]]) -> None:
        self.reasons = reasons[:MAX_REASONS]
        codes = sorted({str(r["code"]) for r in self.reasons})
        super().__init__(", ".join(codes) or "rejected")

    @property
    def codes(self) -> list[str]:
        return sorted({str(r["code"]) for r in self.reasons})


@dataclass(frozen=True)
class Member:
    index: int
    name: str
    size: int  # declared (untrusted)
    compressed: int
    info: zipfile.ZipInfo


@dataclass
class Inspection:
    members: list[Member]  # regular files, manifest excluded, archive order
    manifest: Member
    directories: int
    declared_total: int
    archive_size: int


@dataclass
class MemberResult:
    path: str
    status: str
    index: int | None = None
    size: int | None = None  # actual bytes extracted (declared size for missing members)
    sha256_actual: str | None = None
    sha256_manifest: str | None = None
    file: Path | None = None  # read-only extracted copy, only for verified members
    entry: FileEntry | None = None
    detail: str | None = None

    @property
    def flagged(self) -> bool:
        return self.status in FLAGGED_STATUSES


@dataclass
class BundleResult:
    members: list[MemberResult] = field(default_factory=list)
    bytes_extracted: int = 0

    def counts(self) -> dict[str, int]:
        return dict(sorted(Counter(m.status for m in self.members).items()))

    @property
    def flagged(self) -> list[MemberResult]:
        return [m for m in self.members if m.flagged]


def _safe(value: str, limit: int = 200) -> str:
    return clean_text(repr(value)[1:-1], limit) or ""


def _unix_type(info: zipfile.ZipInfo) -> int:
    return stat.S_IFMT(info.external_attr >> 16)


class BundleReader:
    """``with BundleReader(path, limits) as reader:`` inspect -> manifest -> extract."""

    def __init__(self, path: Path, limits: BundleLimits) -> None:
        self.path = path
        self.limits = limits
        self._zip: zipfile.ZipFile | None = None
        self.inspection: Inspection | None = None

    def __enter__(self) -> BundleReader:
        self.inspection = self._inspect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None

    # ------------------------------------------------------------------ inspection

    def _open(self) -> zipfile.ZipFile:
        with self.path.open("rb") as fh:
            head = fh.read(512)
        if not head.startswith(ZIP_MAGIC):
            code = (
                "unsupported_archive"
                if head.startswith(GZIP_MAGIC) or (len(head) >= 262 and head[257:262] == b"ustar")
                else "not_a_zip"
            )
            raise BundleRejectedError([{"code": code, "detail": "a triage bundle must be a ZIP"}])
        try:
            return zipfile.ZipFile(self.path)
        except (zipfile.BadZipFile, OSError, EOFError, ValueError, NotImplementedError) as exc:
            # UnicodeDecodeError (invalid UTF-8 names) is a ValueError.
            raise BundleRejectedError(
                [{"code": "invalid_zip", "detail": type(exc).__name__}]
            ) from exc

    def _inspect(self) -> Inspection:
        limits = self.limits
        zf = self._open()
        self._zip = zf
        infos = zf.infolist()
        if len(infos) > limits.max_members:
            raise BundleRejectedError(
                [{"code": "too_many_members", "count": len(infos), "limit": limits.max_members}]
            )
        archive_size = self.path.stat().st_size
        reasons: list[dict[str, Any]] = []

        def reject(code: str, name: str | None = None, **extra: Any) -> None:
            if len(reasons) < MAX_REASONS:
                item: dict[str, Any] = {"code": code, **extra}
                if name is not None:
                    item["member"] = _safe(name)
                reasons.append(item)

        exact: set[str] = set()
        folded: set[str] = set()
        spans: list[tuple[int, int, str]] = []
        members: list[Member] = []
        manifest: Member | None = None
        directories = 0
        total = 0
        for index, info in enumerate(infos):
            raw = info.orig_filename
            is_dir = raw.endswith("/")
            reason = unsafe_name_reason(raw, directory=is_dir)
            if reason is None and info.filename != raw:
                reason = "name_ambiguous"  # e.g. a Unicode-path extra field renaming the member
            if reason is not None:
                reject("unsafe_name", raw, reason=reason)
                continue
            key = unicodedata.normalize("NFC", raw).casefold()
            if raw in exact:
                reject("duplicate_name", raw)
            elif key in folded:
                reject("duplicate_name_casefold", raw)
            exact.add(raw)
            folded.add(key)
            if info.flag_bits & 0x1:
                reject("encrypted_member", raw)
            if info.compress_type not in ALLOWED_COMPRESSION:
                reject("unsupported_compression", raw, method=info.compress_type)
            kind = _unix_type(info)
            if kind == stat.S_IFLNK:
                reject("symlink", raw)
            elif kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                reject("special_file", raw, mode=oct(kind))
            if info.external_attr & DOS_REPARSE_POINT:
                reject("reparse_point", raw)
            name_len = len(info.orig_filename.encode("utf-8"))
            spans.append((info.header_offset, info.compress_size + name_len, raw))
            if is_dir or kind == stat.S_IFDIR:
                if info.file_size:
                    reject("directory_with_data", raw)
                directories += 1
                continue
            if info.compress_size > archive_size:
                reject("size_out_of_range", raw)
            if info.file_size > limits.max_member_bytes:
                reject("member_too_large", raw, size=info.file_size)
            if info.file_size > limits.ratio_floor_bytes and (
                info.compress_size == 0 or info.file_size / info.compress_size > limits.max_ratio
            ):
                reject("compression_ratio", raw, size=info.file_size, compressed=info.compress_size)
            total += info.file_size
            member = Member(index, raw, info.file_size, info.compress_size, info)
            if raw == MANIFEST_NAME:
                manifest = member
            else:
                members.append(member)
        if total > limits.max_total_bytes:
            reject("total_too_large", size=total, limit=limits.max_total_bytes)
        if total > limits.ratio_floor_bytes and total / max(archive_size, 1) > limits.max_ratio:
            reject("archive_ratio", size=total, archive_size=archive_size)
        self._check_overlap(spans, getattr(zf, "start_dir", None), reject)
        if manifest is None:
            reject("manifest_missing", detail="manifest.json must be at the archive root")
        elif manifest.size > limits.max_manifest_bytes:
            reject("manifest_too_large", size=manifest.size)
        if reasons:
            raise BundleRejectedError(reasons)
        if manifest is None:  # unreachable (rejected above); narrows the type without assert
            raise BundleRejectedError([{"code": "manifest_missing"}])
        return Inspection(members, manifest, directories, total, archive_size)

    @staticmethod
    def _check_overlap(
        spans: list[tuple[int, int, str]],
        central_start: int | None,
        reject: Callable[..., None],
    ) -> None:
        """Each member's local header + data must end before the next one starts (lower bound:
        fixed header + name + compressed size) and before the central directory."""
        ordered = sorted(spans)
        for (offset, length, name), nxt in zip(ordered, [*ordered[1:], None], strict=True):
            end = offset + LOCAL_HEADER_MIN + length
            if nxt is not None and nxt[0] < end:
                reject("overlapping_entries", nxt[2])
            if central_start is not None and end > central_start:
                reject("overlapping_entries", name)

    # ------------------------------------------------------------------ manifest

    def _require(self) -> tuple[zipfile.ZipFile, Inspection]:
        if self._zip is None or self.inspection is None:
            raise RuntimeError("BundleReader used outside its context")
        return self._zip, self.inspection

    def read_manifest(self) -> tuple[TriageManifest, str]:
        zf, inspection = self._require()
        limit = self.limits.max_manifest_bytes
        try:
            with zf.open(inspection.manifest.info) as src:
                data = src.read(limit + 1)
        except (zipfile.BadZipFile, zlib.error, EOFError, OSError) as exc:
            raise BundleRejectedError(
                [{"code": "manifest_corrupt", "detail": type(exc).__name__}]
            ) from exc
        if len(data) > limit:
            raise BundleRejectedError([{"code": "manifest_too_large"}])
        try:
            return parse_manifest(data)
        except ManifestError as exc:
            raise BundleRejectedError(
                [{"code": "manifest_invalid", "detail": clean_text(str(exc), 400)}]
            ) from exc

    # ------------------------------------------------------------------ extraction

    def extract(
        self,
        dest: Path,
        manifest: TriageManifest,
        progress: Callable[[float], None] = lambda _: None,
    ) -> BundleResult:
        """Extract and verify every member into ``dest`` (created, must not exist)."""
        zf, inspection = self._require()
        dest.mkdir(mode=0o700)
        listed = {entry.path: entry for entry in manifest.files}
        result = BundleResult()
        declared = max(inspection.declared_total, 1)
        since_progress = 0
        for n, member in enumerate(inspection.members):
            entry = listed.pop(member.name, None)
            target = dest / f"{n:05d}.bin"
            outcome = self._extract_one(zf, member, target, result)
            since_progress += outcome.size or 0
            outcome.entry = entry
            if entry is not None:
                outcome.sha256_manifest = entry.sha256
            if outcome.status == VERIFIED:
                if entry is None:
                    outcome.status = "unlisted"
                elif outcome.size != entry.size:
                    outcome.status = "size_mismatch"
                elif outcome.sha256_actual != entry.sha256:
                    outcome.status = "hash_mismatch"
            if outcome.status == VERIFIED:
                os.chmod(target, stat.S_IRUSR)
                outcome.file = target
            result.members.append(outcome)
            if since_progress >= PROGRESS_EVERY or n == len(inspection.members) - 1:
                progress(min(result.bytes_extracted / declared, 1.0))
                since_progress = 0
        for entry in listed.values():
            result.members.append(
                MemberResult(
                    path=entry.path,
                    status="missing",
                    size=entry.size,
                    sha256_manifest=entry.sha256,
                    entry=entry,
                )
            )
        return result

    def _extract_one(
        self, zf: zipfile.ZipFile, member: Member, target: Path, result: BundleResult
    ) -> MemberResult:
        limits = self.limits
        hasher = hashlib.sha256()
        size = 0
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, "wb") as out:
            try:
                with zf.open(member.info) as src:
                    while True:
                        chunk = src.read(READ_CHUNK)
                        if not chunk:
                            break
                        size += len(chunk)
                        result.bytes_extracted += len(chunk)
                        if size > limits.max_member_bytes:
                            raise BundleRejectedError(
                                [{"code": "member_too_large", "member": _safe(member.name)}]
                            )
                        if result.bytes_extracted > limits.max_total_bytes:
                            raise BundleRejectedError(
                                [{"code": "total_too_large", "limit": limits.max_total_bytes}]
                            )
                        hasher.update(chunk)
                        # A write error (disk full) propagates: it is not the bundle's fault.
                        out.write(chunk)
            except (zipfile.BadZipFile, zlib.error, EOFError) as exc:
                return MemberResult(
                    path=member.name,
                    status="corrupt",
                    index=member.index,
                    size=size,
                    detail=type(exc).__name__,
                )
        return MemberResult(
            path=member.name,
            status=VERIFIED,
            index=member.index,
            size=size,
            sha256_actual=hasher.hexdigest(),
        )

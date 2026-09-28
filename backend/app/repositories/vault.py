"""Evidence vault access (MinIO / S3 with Object Lock). The only module that moves evidence bytes.

Originals are written once under ``{case_id}/{evidence_id}/original/<file>`` (guide 8.1) and are
never modified or deleted by the application: this adapter deliberately has no delete or
overwrite API.
Object Lock (COMPLIANCE default retention, ``app/storage.py``) makes the stored version immutable.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from minio import Minio
from minio.error import S3Error

from app.core.hashing import Readable

MIB = 1024 * 1024
READ_CHUNK = 1 * MIB


class VaultObjectMissingError(Exception):
    pass


@dataclass(frozen=True)
class PutResult:
    version_id: str | None
    etag: str | None


@dataclass(frozen=True)
class ObjectInfo:
    size: int
    version_id: str | None
    etag: str | None


@dataclass(frozen=True)
class RetentionInfo:
    mode: str | None
    retain_until: datetime | None


class VaultStore(Protocol):
    bucket: str

    def put_stream(
        self, key: str, reader: Readable, part_size: int, content_type: str
    ) -> PutResult:
        """Store a stream of unknown length; memory bounded by ``part_size``."""

    def iter_object(
        self, key: str, version_id: str | None = None, chunk_size: int = READ_CHUNK
    ) -> Iterator[bytes]: ...

    def stat(self, key: str, version_id: str | None = None) -> ObjectInfo: ...

    def retention(self, key: str, version_id: str | None = None) -> RetentionInfo | None: ...


def object_key(case_id: object, evidence_id: object, filename: str) -> str:
    return f"{case_id}/{evidence_id}/original/{filename}"


def storage_uri(bucket: str, key: str) -> str:
    return f"s3://{bucket}/{key}"


class MinioVault:
    def __init__(self, client: Minio, bucket: str) -> None:
        self.client = client
        self.bucket = bucket

    def put_stream(
        self, key: str, reader: Readable, part_size: int, content_type: str
    ) -> PutResult:
        # length=-1 streams with S3 multipart; one part in flight (no parallel buffering).
        result = self.client.put_object(
            self.bucket,
            key,
            reader,  # type: ignore[arg-type]  # minio only needs .read(n)
            length=-1,
            part_size=part_size,
            content_type=content_type,
            num_parallel_uploads=1,
        )
        return PutResult(version_id=result.version_id, etag=result.etag)

    def iter_object(
        self, key: str, version_id: str | None = None, chunk_size: int = READ_CHUNK
    ) -> Iterator[bytes]:
        try:
            response = self.client.get_object(self.bucket, key, version_id=version_id)
        except S3Error as exc:
            if exc.code in {"NoSuchKey", "NoSuchVersion", "InvalidArgument"}:
                raise VaultObjectMissingError(key) from exc
            raise
        try:
            yield from response.stream(chunk_size)
        finally:
            response.close()
            response.release_conn()

    def stat(self, key: str, version_id: str | None = None) -> ObjectInfo:
        try:
            obj = self.client.stat_object(self.bucket, key, version_id=version_id)
        except S3Error as exc:
            if exc.code in {"NoSuchKey", "NoSuchVersion", "InvalidArgument"}:
                raise VaultObjectMissingError(key) from exc
            raise
        return ObjectInfo(size=int(obj.size or 0), version_id=obj.version_id, etag=obj.etag)

    def retention(self, key: str, version_id: str | None = None) -> RetentionInfo | None:
        try:
            ret = self.client.get_object_retention(self.bucket, key, version_id=version_id)
        except S3Error as exc:
            if exc.code in {
                "NoSuchObjectLockConfiguration",
                "ObjectLockConfigurationNotFoundError",
            }:
                return None
            raise
        if ret is None:
            return None
        return RetentionInfo(mode=ret.mode, retain_until=ret.retain_until_date)

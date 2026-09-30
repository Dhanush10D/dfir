"""Report artifact storage (the ``artifacts`` bucket). Artifacts are derived work products, not
evidence: they are written once per signed report version under
``reports/{case_id}/{family_id}/v{version}/{name}`` and always re-verified against the signed
manifest when read, so a changed object is detected rather than trusted.
"""

from __future__ import annotations

import io
from typing import Protocol

from minio import Minio
from minio.error import S3Error

MAX_ARTIFACT_BYTES = 256 * 1024 * 1024


class ArtifactMissingError(Exception):
    pass


class ArtifactStore(Protocol):
    bucket: str

    def put_bytes(self, key: str, data: bytes, content_type: str) -> None: ...

    def get_bytes(self, key: str, max_bytes: int = MAX_ARTIFACT_BYTES) -> bytes: ...


def artifact_prefix(case_id: object, family_id: object, version: int) -> str:
    return f"reports/{case_id}/{family_id}/v{version}/"


class MinioArtifactStore:
    def __init__(self, client: Minio, bucket: str) -> None:
        self.client = client
        self.bucket = bucket

    def put_bytes(self, key: str, data: bytes, content_type: str) -> None:
        self.client.put_object(
            self.bucket, key, io.BytesIO(data), length=len(data), content_type=content_type
        )

    def get_bytes(self, key: str, max_bytes: int = MAX_ARTIFACT_BYTES) -> bytes:
        try:
            response = self.client.get_object(self.bucket, key)
        except S3Error as exc:
            if exc.code in {"NoSuchKey", "NoSuchBucket"}:
                raise ArtifactMissingError(key) from exc
            raise
        try:
            data = response.read(max_bytes + 1)
        finally:
            response.close()
            response.release_conn()
        if len(data) > max_bytes:
            raise ArtifactMissingError(f"{key} is larger than {max_bytes} bytes")
        return data

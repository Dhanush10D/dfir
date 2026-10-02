"""Evidence vault against a real MinIO (compose, or S3_* env in CI). Skipped when unreachable.

Uses a throwaway Object-Lock bucket in GOVERNANCE mode (1 day) so the test objects can be cleaned
up with the governance bypass; the real vault uses COMPLIANCE mode, which nobody can bypass.
"""

from __future__ import annotations

import hashlib
import io
import os
import uuid
import warnings
from collections.abc import Iterator

import pytest
from minio import Minio
from minio.commonconfig import GOVERNANCE
from minio.deleteobjects import DeleteObject
from minio.error import S3Error
from minio.objectlockconfig import DAYS, ObjectLockConfig

from app.config import Settings
from app.core.hashing import HashingReader, hash_chunks
from app.db.models import UserRole
from app.repositories.vault import MIB, MinioVault
from app.storage import make_minio_client
from tests.integration.harness import Harness

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def minio_client() -> Minio:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]  # S3_* from env or defaults
    client = make_minio_client(settings, timeout_s=5.0, retries=0)
    try:
        client.bucket_exists("dfirtest-probe")
    except Exception as exc:  # noqa: BLE001
        pytest.skip(
            "MinIO not reachable (start it with `docker compose -f infra/compose.yaml up -d minio` "
            f"or set S3_ENDPOINT/S3_ACCESS_KEY/S3_SECRET_KEY): {type(exc).__name__}"
        )
    return make_minio_client(settings, timeout_s=60.0, retries=1)


TEST_BUCKET_PREFIX = "dfirtest-"


def purge_bucket(client: Minio, name: str, attempts: int = 3) -> bool:
    """Best effort: delete every version and delete marker (governance bypass), then the bucket.

    Only ever used on ``dfirtest-*`` buckets (GOVERNANCE mode); never on the real vault.
    """
    assert name.startswith(TEST_BUCKET_PREFIX)
    for _ in range(attempts):
        try:
            versions = [
                DeleteObject(o.object_name, o.version_id)
                for o in client.list_objects(name, recursive=True, include_version=True)
                if o.object_name
            ]
            errors = list(client.remove_objects(name, versions, bypass_governance_mode=True))
            if errors:
                continue
            client.remove_bucket(name)
            return True
        except S3Error as exc:
            if exc.code == "NoSuchBucket":
                return True
    warnings.warn(f"could not remove MinIO test bucket {name}", stacklevel=2)
    return False


@pytest.fixture(scope="module")
def worm_bucket(minio_client: Minio) -> Iterator[str]:
    # Sweep buckets leaked by earlier interrupted runs (only our own test prefix).
    for bucket in minio_client.list_buckets():
        if bucket.name.startswith(TEST_BUCKET_PREFIX):
            purge_bucket(minio_client, bucket.name, attempts=1)
    name = f"{TEST_BUCKET_PREFIX}{uuid.uuid4().hex[:12]}"
    minio_client.make_bucket(name, object_lock=True)
    minio_client.set_object_lock_config(name, ObjectLockConfig(GOVERNANCE, 1, DAYS))
    try:
        yield name
    finally:
        purge_bucket(minio_client, name)


def test_purge_removes_locked_versions(minio_client: Minio) -> None:
    name = f"{TEST_BUCKET_PREFIX}{uuid.uuid4().hex[:12]}"
    minio_client.make_bucket(name, object_lock=True)
    minio_client.set_object_lock_config(name, ObjectLockConfig(GOVERNANCE, 1, DAYS))
    for i in range(3):  # several versions of one key, all under retention
        minio_client.put_object(name, "k", io.BytesIO(b"v%d" % i), 2)
    assert purge_bucket(minio_client, name)
    assert not minio_client.bucket_exists(name)


@pytest.fixture
def vault(minio_client: Minio, worm_bucket: str) -> MinioVault:  # overrides the fake vault
    return MinioVault(minio_client, worm_bucket)


def test_streaming_multipart_upload_hash_matches_independent_digest(vault: MinioVault) -> None:
    data = os.urandom(3 * MIB) * 4 + b"tail"  # 12 MiB + 4 bytes -> three 5 MiB parts
    reader = HashingReader(io.BytesIO(data), max_bytes=64 * MIB)
    key = f"case/{uuid.uuid4()}/original/mem.raw"
    result = vault.put_stream(
        key, reader, part_size=5 * MIB, content_type="application/octet-stream"
    )
    digests = reader.hasher.digests()
    assert digests.sha256 == hashlib.sha256(data).hexdigest()
    assert digests.size == len(data)
    assert reader.max_read <= 5 * MIB + 1  # never more than one part in memory
    assert result.version_id
    info = vault.stat(key)
    assert info.size == len(data) and info.version_id == result.version_id
    assert hash_chunks(vault.iter_object(key, result.version_id)).sha256 == digests.sha256
    retention = vault.retention(key, result.version_id)
    assert retention is not None and retention.mode == GOVERNANCE and retention.retain_until


def test_locked_original_cannot_be_deleted(vault: MinioVault, minio_client: Minio) -> None:
    key = f"case/{uuid.uuid4()}/original/a.log"
    result = vault.put_stream(key, io.BytesIO(b"immutable"), 5 * MIB, "text/plain")
    with pytest.raises(S3Error):
        minio_client.remove_object(vault.bucket, key, version_id=result.version_id)
    assert hash_chunks(vault.iter_object(key, result.version_id)).size == len(b"immutable")


def test_api_flow_against_real_vault_and_overwrite_detection(
    h: Harness, minio_client: Minio, vault: MinioVault
) -> None:
    lead = h.make_user(UserRole.lead)
    case = h.create_case(lead)
    data = os.urandom(6 * MIB + 123)
    ev = h.create_evidence(lead, case["id"], kind="memory", original_name="host.mem")
    assert ev["storage_uri"].startswith(f"s3://{vault.bucket}/")
    r = h.upload(lead, ev["id"], data)
    assert r.status_code == 200, r.text
    assert r.json()["sha256"] == hashlib.sha256(data).hexdigest()
    fin = h.post(f"/evidence/{ev['id']}/finalize", lead).json()
    assert fin["ok"] is True and fin["retention_mode"] == GOVERNANCE
    assert h.post(f"/evidence/{ev['id']}/verify", lead).json()["ok"] is True

    auditor = h.make_user(UserRole.auditor)
    download = h.get(f"/evidence/{ev['id']}/download", auditor)
    assert download.status_code == 200
    assert hashlib.sha256(download.content).hexdigest() == hashlib.sha256(data).hexdigest()

    # An attacker with bucket write access puts a new version at the original's key.
    key = h.key_of(ev)
    tampered = bytearray(data)
    tampered[100] ^= 0x01
    minio_client.put_object(vault.bucket, key, io.BytesIO(bytes(tampered)), len(tampered))
    report = h.post(f"/evidence/{ev['id']}/verify", lead).json()
    assert report["ok"] is False
    assert {p["code"] for p in report["object"]["problems"]} == {"object_replaced"}
    # The locked original version is untouched and still verifies byte for byte.
    assert report["object"]["actual"]["sha256"] == hashlib.sha256(data).hexdigest()


def test_delete_marker_does_not_hide_the_intact_original(
    h: Harness, minio_client: Minio, vault: MinioVault
) -> None:
    lead = h.make_user(UserRole.lead)
    case = h.create_case(lead)
    data = os.urandom(MIB + 7)
    ev = h.create_evidence(lead, case["id"], kind="memory", original_name="host2.mem")
    assert h.upload(lead, ev["id"], data).status_code == 200
    assert h.post(f"/evidence/{ev['id']}/finalize", lead).json()["ok"] is True
    # A plain DELETE under Object Lock only adds a delete marker on top of the locked version.
    minio_client.remove_object(vault.bucket, h.key_of(ev))
    report = h.post(f"/evidence/{ev['id']}/verify", lead).json()
    assert {p["code"] for p in report["object"]["problems"]} == {"delete_marker_at_key"}
    assert report["object"]["actual"]["sha256"] == hashlib.sha256(data).hexdigest()


def test_artifact_store_roundtrip(minio_client: Minio) -> None:
    """Phase 8: report artifacts in a plain bucket; missing and oversized objects are errors."""
    from app.repositories.artifacts import ArtifactMissingError, MinioArtifactStore

    bucket = f"{TEST_BUCKET_PREFIX}art-{uuid.uuid4().hex[:8]}"
    minio_client.make_bucket(bucket)
    try:
        store = MinioArtifactStore(minio_client, bucket)
        store.put_bytes("reports/c/f/v1/report.html", b"<html>x</html>", "text/html")
        assert store.get_bytes("reports/c/f/v1/report.html") == b"<html>x</html>"
        with pytest.raises(ArtifactMissingError):
            store.get_bytes("reports/c/f/v1/missing.pdf")
        with pytest.raises(ArtifactMissingError, match="larger than"):
            store.get_bytes("reports/c/f/v1/report.html", max_bytes=4)
    finally:
        purge_bucket(minio_client, bucket)

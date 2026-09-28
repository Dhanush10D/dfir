"""Evidence lifecycle over the API (fake vault): create, upload, finalize, verify, download."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from sqlalchemy import text

from app.db.models import UserRole
from tests.fakes import FakeVault
from tests.integration.harness import Harness

pytestmark = pytest.mark.integration


def _actions(h: Harness, user: Any, evidence_id: str) -> list[str]:
    r = h.get(f"/evidence/{evidence_id}/custody", user)
    assert r.status_code == 200, r.text
    return [e["action"] for e in r.json()["entries"]]


def test_full_lifecycle(h: Harness, vault: FakeVault) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    data = b"Sep 14 09:00:01 host sshd[1]: Failed password for root\n" * 1000
    ev = h.create_evidence(
        analyst,
        case["id"],
        original_name="../../etc/auth.log",
        source_host="WS-042",
        acquired_at="2026-09-14T09:00:00Z",
        acquired_by="J. Kumar",
        acquisition_tool="collector 1.0",
        expected_sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )
    assert ev["label"] == "EV-001"
    assert ev["status"] == "uploading"
    # Client file names never become paths.
    assert ev["storage_uri"] == f"s3://evidence/{case['id']}/{ev['id']}/original/auth.log"

    r = h.upload(analyst, ev["id"], data)
    assert r.status_code == 200, r.text
    uploaded = r.json()
    assert uploaded["status"] == "uploaded"
    assert uploaded["sha256"] == hashlib.sha256(data).hexdigest()
    assert uploaded["md5"] == hashlib.md5(data).hexdigest()
    assert uploaded["size_bytes"] == len(data)
    assert uploaded["storage_version_id"]

    r = h.post(f"/evidence/{ev['id']}/finalize", analyst)
    assert r.status_code == 200, r.text
    fin = r.json()
    assert fin["ok"] is True
    assert fin["evidence"]["status"] == "stored"
    assert fin["retention_mode"] == "COMPLIANCE"
    assert fin["evidence"]["retain_until"]

    r = h.post(f"/evidence/{ev['id']}/verify", analyst)
    assert r.status_code == 200, r.text
    ver = r.json()
    assert ver["ok"] is True and ver["status"] == "verified"
    assert ver["chain"]["ok"] is True and ver["chain"]["problems"] == []
    assert ver["object"]["actual"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert ver["custody_entry"]["action"] == "hash_verified"

    assert _actions(h, analyst, ev["id"]) == [
        "created",
        "ingested",
        "hash_verified",
        "locked",
        "hash_verified",
    ]
    second = h.create_evidence(analyst, case["id"])
    assert second["label"] == "EV-002"


def test_upload_twice_is_refused(h: Harness) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    ev = h.create_evidence(analyst, case["id"])
    assert h.upload(analyst, ev["id"], b"abc").status_code == 200
    r = h.upload(analyst, ev["id"], b"different")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "invalid_state"


def test_expected_hash_mismatch_fails_finalize(h: Harness) -> None:
    analyst = h.make_user(UserRole.analyst)
    admin = h.make_user(UserRole.admin)
    case = h.create_case(analyst)
    ev = h.create_evidence(analyst, case["id"], expected_sha256="0" * 64)
    assert h.upload(analyst, ev["id"], b"payload").status_code == 200
    r = h.post(f"/evidence/{ev['id']}/finalize", analyst)
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert body["evidence"]["status"] == "failed"
    assert [m["field"] for m in body["mismatches"]] == ["expected_sha256"]
    assert _actions(h, analyst, ev["id"])[-1] == "hash_failed"
    with h.engine.connect() as conn:
        kinds = conn.execute(
            text("SELECT kind FROM notifications WHERE user_id = :u"), {"u": admin.id}
        ).scalars()
        assert "evidence.verification_failed" in set(kinds)


def test_declared_size_mismatch_fails_finalize(h: Harness) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    ev = h.create_evidence(analyst, case["id"], size_bytes=999)
    assert h.upload(analyst, ev["id"], b"12345").status_code == 200
    body = h.post(f"/evidence/{ev['id']}/finalize", analyst).json()
    assert body["ok"] is False
    assert body["mismatches"] == [{"field": "declared_size", "expected": 999, "actual": 5}]


def test_oversize_upload_is_rejected_and_nothing_stored(
    h: Harness, vault: FakeVault, monkeypatch: pytest.MonkeyPatch
) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    ev = h.create_evidence(analyst, case["id"])
    monkeypatch.setattr(type(h.settings), "max_upload_bytes", property(lambda self: 10))
    r = h.upload(analyst, ev["id"], b"x" * 11)
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "upload_too_large"
    assert h.key_of(ev) not in vault.objects
    monkeypatch.undo()
    # Nothing was recorded, so a correct retry is still possible.
    assert h.get(f"/evidence/{ev['id']}", analyst).json()["status"] == "uploading"
    assert h.upload(analyst, ev["id"], b"ok").status_code == 200


def test_vault_failure_mid_stream_leaves_evidence_retryable(h: Harness, vault: FakeVault) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    ev = h.create_evidence(analyst, case["id"])
    vault.fail_after_bytes = 3
    r = h.upload(analyst, ev["id"], b"abcdef")
    assert r.status_code == 502
    assert r.json()["error"]["code"] == "upload_failed"
    vault.fail_after_bytes = None
    assert h.get(f"/evidence/{ev['id']}", analyst).json()["status"] == "uploading"
    assert _actions(h, analyst, ev["id"]) == ["created"]


def test_upload_is_streamed_in_bounded_parts(h: Harness, vault: FakeVault) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    ev = h.create_evidence(analyst, case["id"], kind="memory", original_name="mem.raw")
    part = h.settings.upload_part_size_mb * 1024 * 1024
    chunk = b"\x5a" * (256 * 1024)
    total_chunks = 48  # 12 MiB, more than two parts

    def body() -> Any:
        for _ in range(total_chunks):
            yield chunk

    r = h.put(
        f"/evidence/{ev['id']}/upload",
        analyst,
        content=body(),
        headers={"Content-Type": "application/octet-stream"},
    )
    assert r.status_code == 200, r.text
    expected = hashlib.sha256(chunk * total_chunks).hexdigest()
    assert r.json()["sha256"] == expected
    assert r.json()["size_bytes"] == len(chunk) * total_chunks
    assert 0 < vault.max_read_seen <= part


def test_multipart_form_upload_is_refused(h: Harness) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    ev = h.create_evidence(analyst, case["id"])
    r = h.put(f"/evidence/{ev['id']}/upload", analyst, files={"f": ("a.txt", b"abc")})
    assert r.status_code == 415


def test_download_streams_original_and_logs_custody(h: Harness) -> None:
    lead = h.make_user(UserRole.lead)
    case = h.create_case(lead)
    data = bytes(range(256)) * 10
    ev = h.stored_evidence(lead, case["id"], data)
    r = h.get(f"/evidence/{ev['id']}/download", lead)
    assert r.status_code == 200
    assert r.content == data
    assert r.headers["x-evidence-sha256"] == hashlib.sha256(data).hexdigest()
    assert 'filename="auth.log"' in r.headers["content-disposition"]
    assert _actions(h, lead, ev["id"])[-1] == "downloaded"


def test_evidence_validation_errors(h: Harness) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    r = h.post(
        f"/cases/{case['id']}/evidence", analyst, json={"kind": "nope", "original_name": "x"}
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_kind"
    r = h.post(
        f"/cases/{case['id']}/evidence",
        analyst,
        json={"kind": "log", "original_name": "x", "label": "../bad"},
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_label"
    h.create_evidence(analyst, case["id"], label="DISK-1")
    r = h.post(
        f"/cases/{case['id']}/evidence",
        analyst,
        json={"kind": "log", "original_name": "x", "label": "DISK-1"},
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "label_taken"


def test_finalize_requires_uploaded_state(h: Harness) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    ev = h.create_evidence(analyst, case["id"])
    assert h.post(f"/evidence/{ev['id']}/finalize", analyst).status_code == 409
    assert h.post(f"/evidence/{ev['id']}/verify", analyst).status_code == 409
    assert h.get(f"/evidence/{ev['id']}/download", h.make_user(UserRole.admin)).status_code == 409


def test_missing_signer_blocks_writes_but_not_reads(h: Harness) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    ev = h.create_evidence(analyst, case["id"])
    h.signer = None
    r = h.post(f"/cases/{case['id']}/evidence", analyst, json={"kind": "log", "original_name": "a"})
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "custody_signer_unavailable"
    assert h.get(f"/evidence/{ev['id']}/custody", analyst).status_code == 200


def test_signing_keys_are_published(h: Harness) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    h.create_evidence(analyst, case["id"])
    r = h.get("/signing-keys", analyst)
    assert r.status_code == 200
    keys = {k["key_id"]: k for k in r.json()}
    assert keys["test-custody-1"]["algorithm"] == "ed25519"
    assert "BEGIN PUBLIC KEY" in keys["test-custody-1"]["public_key"]

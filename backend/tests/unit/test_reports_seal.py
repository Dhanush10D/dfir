"""Report seal (manifest hash + Ed25519), evidence export package and the offline verify CLI."""

from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.signing import CustodySigner, public_key_pem
from app.reports import verify as verify_cli
from app.reports.package import build_evidence_package, verify_package
from app.reports.seal import (
    Artifact,
    build_manifest,
    canonical_json,
    manifest_sha256,
    verify_manifest_signature,
)
from app.services.custody import GENESIS, build_entry

EV = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def signer() -> CustodySigner:
    return CustodySigner("ed25519-test", Ed25519PrivateKey.generate())


def manifest(signer: CustodySigner, data: bytes = b"<html></html>") -> dict[str, Any]:
    return build_manifest(
        report_id="r",
        family_id="r",
        version=1,
        case_id="c",
        case_number="IR-1",
        kind="technical",
        context_sha256="1" * 64,
        content_sha256="2" * 64,
        render_meta={"status": "signed"},
        artifacts=[
            Artifact("report.pdf", "pdf", "application/pdf", b"%PDF"),
            Artifact("report.html", "html", "text/html", data),
        ],
        signed_at="2026-09-30T11:00:00Z",
        key_id=signer.key_id,
    )


def test_canonical_json_is_stable_and_rejects_nan() -> None:
    assert canonical_json({"b": 1, "a": [1, "x"]}) == b'{"a":[1,"x"],"b":1}'
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_manifest_signature_verifies_and_detects_tampering(signer: CustodySigner) -> None:
    m = manifest(signer)
    assert [a["name"] for a in m["artifacts"]] == ["report.html", "report.pdf"]
    digest = manifest_sha256(m)
    sig = signer.sign(digest)
    keys = {signer.key_id: signer.public_key}
    assert verify_manifest_signature(m, digest, sig, keys).ok
    tampered = json.loads(json.dumps(m))
    tampered["artifacts"][0]["sha256"] = "0" * 64
    check = verify_manifest_signature(tampered, digest, sig, keys)
    assert not check.ok and check.problems[0]["code"] == "manifest_hash_mismatch"
    other = CustodySigner("ed25519-test", Ed25519PrivateKey.generate())
    assert not verify_manifest_signature(m, digest, sig, {signer.key_id: other.public_key}).ok
    untrusted = verify_manifest_signature(m, digest, sig, {})
    assert {p["code"] for p in untrusted.problems} == {"untrusted_key"}


def chain(signer: CustodySigner) -> list[dict[str, Any]]:
    entries, prev = [], GENESIS
    for seq, action in enumerate(("created", "ingested", "hash_verified"), start=1):
        e = build_entry(
            signer,
            evidence_id=EV,
            seq=seq,
            ts=datetime(2026, 9, 2, 9, seq, tzinfo=UTC),
            actor_id=None,
            actor_label="Ana <ana@example.org>",
            action=action,
            detail={"sha256": "a" * 64},
            prev_hash=prev,
        )
        prev = e.entry_hash
        entries.append(
            {
                "evidence_id": e.evidence_id,
                "seq": e.seq,
                "ts": f"2026-09-02T09:{seq:02d}:00.000000Z",
                "actor_id": None,
                "actor_label": e.actor_label,
                "action": e.action,
                "detail": e.detail,
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
                "signature": e.signature,
                "key_id": e.key_id,
            }
        )
    return entries


def package(signer: CustodySigner) -> bytes:
    return build_evidence_package(
        {"evidence": {"id": EV, "sha256": "a" * 64}, "exported_by": "Ana"},
        {"evidence_id": EV, "entries": chain(signer)},
        signer,
    )


def rezip(data: bytes, name: str, new: bytes) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as dst:
        for info in src.infolist():
            dst.writestr(info, new if info.filename == name else src.read(info))
    return out.getvalue()


def test_package_is_deterministic_and_verifies(signer: CustodySigner) -> None:
    data = package(signer)
    assert data == package(signer)
    assert sorted(zipfile.ZipFile(io.BytesIO(data)).namelist()) == [
        "custody.json",
        "manifest.json",
        "manifest.sig",
    ]
    result = verify_package(data, {signer.key_id: signer.public_key})
    assert result["ok"], result
    assert result["custody_chain_ok"] is True and result["evidence_sha256"] == "a" * 64


def test_package_tampering_is_detected(signer: CustodySigner) -> None:
    data = package(signer)
    keys = {signer.key_id: signer.public_key}
    manifest_doc = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("manifest.json"))
    manifest_doc["evidence"]["sha256"] = "f" * 64
    bad = rezip(data, "manifest.json", json.dumps(manifest_doc).encode())
    assert "manifest_hash_mismatch" in {p["code"] for p in verify_package(bad, keys)["problems"]}
    # a consistent re-sign with another key is not trusted
    attacker = CustodySigner(signer.key_id, Ed25519PrivateKey.generate())
    forged = verify_package(package(attacker), keys)
    assert not forged["ok"] and "bad_signature" in {p["code"] for p in forged["problems"]}
    # the embedded public key is never trusted by itself
    assert not verify_package(data, {})["ok"]
    # an edited custody entry is caught by the chain check even inside a validly signed package
    entries = chain(signer)
    entries[1]["detail"] = {"sha256": "f" * 64}
    signed_bad = build_evidence_package(
        {"evidence": {"id": EV}}, {"evidence_id": EV, "entries": entries}, signer
    )
    result = verify_package(signed_bad, keys)
    assert not result["ok"] and result["custody_chain_ok"] is False
    assert "custody_chain_invalid" in {p["code"] for p in result["problems"]}


def test_malformed_packages(signer: CustodySigner) -> None:
    keys = {signer.key_id: signer.public_key}
    assert verify_package(b"not a zip", keys)["problems"][0]["code"] == "malformed"
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("../../evil", b"x")
    assert not verify_package(out.getvalue(), keys)["ok"]


def test_verify_cli_package_and_report(
    signer: CustodySigner, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pkg = tmp_path / "EV-001_package.zip"
    pkg.write_bytes(package(signer))
    pem = tmp_path / "pub.pem"
    pem.write_text(public_key_pem(signer.public_key), encoding="ascii")
    args = ["--public-key", str(pem), "--key-id", signer.key_id]
    assert verify_cli.main(["package", str(pkg), *args]) == 0
    keys_file = tmp_path / "trusted.json"
    keys_file.write_text(json.dumps({signer.key_id: public_key_pem(signer.public_key)}))
    assert verify_cli.main(["package", str(pkg), "--keys", str(keys_file)]) == 0
    assert verify_cli.main(["package", str(pkg)]) == 2  # no trusted keys
    # report seal + artifact files
    html = b"<html>report</html>"
    m = manifest(signer, html)
    digest = manifest_sha256(m)
    seal = {"manifest": m, "manifest_sha256": digest, "signature": signer.sign(digest)}
    (tmp_path / "seal.json").write_text(json.dumps(seal))
    (tmp_path / "report.html").write_bytes(html)
    capsys.readouterr()
    assert verify_cli.main(["report", str(tmp_path / "seal.json"), *args]) == 0
    out = json.loads(capsys.readouterr().out)
    assert {a["name"]: a["ok"] for a in out["artifacts"]} == {
        "report.html": True,
        "report.pdf": None,
    }
    (tmp_path / "report.html").write_bytes(html + b"<!-- tampered -->")
    assert verify_cli.main(["report", str(tmp_path / "seal.json"), *args]) == 1

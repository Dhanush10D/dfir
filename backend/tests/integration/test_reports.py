"""Phase 8: reports and evidence export packages end to end through the API.

Covers the snapshot, edits with optimistic concurrency, the QA gate, four-eyes approval, signing
(artifacts + manifest + Ed25519), verification (trusted keys only, stored hashes, byte-identical
re-render) and tamper detection, downloads with their headers, versions, RBAC and case
isolation, closed cases, AI drafts (accepted only, labelled), the custody/IOC kinds, hostile
evidence text, the evidence export package with its custody entry, and the DB guard and grants.
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import stix2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

import app.services.reports as report_service
from app.core.signing import CustodySigner
from app.db.models import Alert, AlertEvent, Event, Severity, UserRole
from app.reports.package import verify_package
from app.reports.render_pdf import RenderLimitError
from app.reports.verify import verify_report_seal
from tests.integration.harness import Harness, UserCtx

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
AUTH_LOG = (FIXTURES / "linux" / "auth.log").read_bytes()
T0 = datetime(2026, 9, 14, 8, 0, tzinfo=UTC)
HOSTILE = '<script>alert("pwn")</script><img src=http://evil.example/x onerror=alert(1)>'


class World:
    def __init__(self, h: Harness) -> None:
        self.h = h
        self.lead = h.make_user(UserRole.lead)
        self.lead2 = h.make_user(UserRole.lead)
        self.analyst = h.make_user(UserRole.analyst)
        self.viewer = h.make_user(UserRole.viewer)
        self.auditor = h.make_user(UserRole.auditor)
        self.outsider = h.make_user(UserRole.analyst)
        self.cid = h.create_case(self.lead, "Report case")["id"]
        for user, role in (
            (self.analyst, UserRole.analyst),
            (self.viewer, UserRole.viewer),
            (self.lead2, UserRole.lead),
        ):
            h.add_member(self.lead, self.cid, user, role)
        self.evidence = h.stored_evidence(
            self.analyst, self.cid, AUTH_LOG, original_name="auth" + HOSTILE + ".log"
        )
        r = h.post(
            f"/evidence/{self.evidence['id']}/process",
            self.analyst,
            json={"parsers": ["linux_auth"]},
        )
        assert r.status_code == 202, r.text
        assert {x.outcome for x in h.run_pending()} == {"succeeded"}
        self.add_synthetic()
        r = h.post(
            f"/cases/{self.cid}/bookmarks",
            self.analyst,
            json={"target_type": "event", "target_id": str(self.bookmarked_id)},
        )
        assert r.status_code == 201, r.text
        r = h.post(
            f"/cases/{self.cid}/iocs",
            self.analyst,
            json={"type": "domain", "value": "evil.example", "tlp": "amber", "confidence": 0.8},
        )
        assert r.status_code == 201, r.text

    def add_synthetic(self) -> None:
        cid = uuid.UUID(self.cid)
        self.bookmarked_id = uuid.uuid4()
        self.alert_event_id = uuid.uuid4()
        rows = [
            Event(
                id=self.bookmarked_id,
                case_id=cid,
                ts=T0,
                source_type="evtx",
                parser_name="synthetic",
                host="WS-042",
                user="bob",
                event_code="4688",
                process_name="powershell.exe",
                cmdline="=cmd|' /C calc'!A0 " + HOSTILE,
                evidence_id=uuid.UUID(self.evidence["id"]),
            ),
            Event(
                id=self.alert_event_id,
                case_id=cid,
                ts=T0 + timedelta(minutes=1),
                source_type="evtx",
                parser_name="synthetic",
                host="WS-042",
                user="bob",
                event_code="4625",
                message="Failed logon " + HOSTILE,
                attack_tags=["T1110"],
            ),
        ]
        with self.h.sessions() as session:
            session.add_all(rows)
            alert = Alert(
                case_id=cid,
                rule_id=None,
                title="Brute force " + HOSTILE,
                severity=Severity.high,
                host="WS-042",
                user="bob",
                attack_tags=["T1110"],
                dedup_key=f"synthetic-{uuid.uuid4().hex}",
                first_seen=T0,
                last_seen=T0 + timedelta(minutes=1),
                event_count=1,
            )
            session.add(alert)
            session.flush()
            session.add(
                AlertEvent(
                    alert_id=alert.id,
                    event_id=self.alert_event_id,
                    event_ts=T0 + timedelta(minutes=1),
                )
            )
            session.commit()
            self.alert_id = str(alert.id)

    # ------------------------------------------------------------------ helpers

    def create(self, kind: str = "technical", user: UserCtx | None = None) -> dict[str, Any]:
        r = self.h.post(f"/cases/{self.cid}/reports", user or self.analyst, json={"kind": kind})
        assert r.status_code == 201, r.text
        return dict(r.json())

    def patch(self, report: dict[str, Any], user: UserCtx | None = None, **body: Any) -> Any:
        return self.h.patch(
            f"/reports/{report['id']}",
            user or self.analyst,
            json={"expected_revision": report["revision"], **body},
        )

    def finding(self, **over: Any) -> dict[str, Any]:
        return {
            "title": "Brute force then execution",
            "body": "Failed logons were followed by **PowerShell**. " + HOSTILE,
            "confidence": "high",
            "attack": ["T1110", "t1059.001"],
            "refs": [
                {"type": "event", "id": str(self.bookmarked_id)},
                {"type": "alert", "id": self.alert_id},
                {"type": "evidence", "id": self.evidence["id"]},
            ],
            **over,
        }

    def fill(self, report: dict[str, Any], user: UserCtx | None = None) -> dict[str, Any]:
        texts = {sd["name"]: f"Text for {sd['title']}. " + HOSTILE for sd in report["section_defs"]}
        r = self.patch(report, user, sections=texts, findings=[self.finding()])
        assert r.status_code == 200, r.text
        return dict(r.json())

    def signed(self, kind: str = "technical") -> dict[str, Any]:
        report = self.fill(self.create(kind))
        h = self.h
        r = h.post(
            f"/reports/{report['id']}/submit",
            self.analyst,
            json={"expected_revision": report["revision"]},
        )
        assert r.status_code == 200, r.text
        assert h.post(f"/reports/{report['id']}/approve", self.lead).status_code == 200
        r = h.post(f"/reports/{report['id']}/sign", self.lead)
        assert r.status_code == 200, r.text
        return dict(r.json())


@pytest.fixture
def world(h: Harness) -> World:
    return World(h)


def _audit(db: Engine, action: str, object_id: str) -> list[dict[str, Any]]:
    with db.connect() as conn:
        rows = conn.execute(
            text("SELECT detail FROM audit_log WHERE action = :a AND object_id = :o ORDER BY id"),
            {"a": action, "o": object_id},
        ).scalars()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------------- lifecycle


def test_full_lifecycle_technical(world: World, db_engine: Engine, signer: CustodySigner) -> None:
    h = world.h
    report = world.create()
    rid = report["id"]
    assert report["status"] == "draft" and report["version"] == 1 and report["family_id"] == rid
    assert report["counts"]["evidence"] == 1 and report["counts"]["key_events"] == 2
    assert report["sections"]["methodology"]["origin"] == "template"
    detail = h.get(f"/reports/{rid}?include_context=true", world.viewer).json()
    ctx = detail["context"]
    assert {e["reasons"][0] for e in ctx["key_events"]} == {"alert", "bookmark"}
    assert ctx["evidence"][0]["custody_ok"] is True and ctx["custody"][0]["ok"] is True
    assert ctx["iocs"][0]["value"] == "evil.example" and ctx["runs"][0]["parser"] == "linux_auth"
    assert set(ctx["input_hashes"]) >= {"evidence", "custody", "alerts", "key_events", "iocs"}
    assert _audit(db_engine, "report.create", rid)[0]["context_sha256"] == report["context_sha256"]

    # QA fails: empty required sections, a TODO, a finding without evidence
    r = world.patch(
        report,
        sections={"scope": "Scope TODO"},
        findings=[{"title": "Unsupported", "body": "no refs"}],
    )
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["revision"] == 1 and report["findings"][0]["origin"] == "analyst"
    qa = h.post(f"/reports/{rid}/qa", world.analyst).json()["qa"]
    codes = {e["code"] for e in qa["errors"]}
    assert {"section_empty", "unresolved_marker", "finding_without_evidence"} <= codes
    r = h.post(f"/reports/{rid}/submit", world.analyst, json={"expected_revision": 1})
    assert r.status_code == 409 and r.json()["error"]["code"] == "qa_failed"

    # stale edit
    stale = world.patch({"id": rid, "revision": 0}, title="x")
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "stale_revision"
    # a reference from another case / unknown id is refused
    bad = world.patch(
        report, findings=[world.finding(refs=[{"type": "event", "id": str(uuid.uuid4())}])]
    )
    assert bad.status_code == 404
    report = world.fill(report)
    ref_labels = [r["type"] for r in report["findings"][0]["refs"]]
    assert ref_labels == ["event", "alert", "evidence"]
    assert report["findings"][0]["attack"] == ["T1059.001", "T1110"]
    r = h.post(
        f"/reports/{rid}/submit", world.analyst, json={"expected_revision": report["revision"]}
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "in_review" and r.json()["qa"]["ok"] is True
    # content is frozen while in review
    assert world.patch(r.json(), title="late").status_code == 409

    # the analyst cannot approve or sign; a lead cannot sign before approval
    assert h.post(f"/reports/{rid}/approve", world.analyst).status_code == 403
    assert h.post(f"/reports/{rid}/sign", world.lead).status_code == 409
    # four eyes: the submitter (here a lead) cannot approve
    assert (
        h.post(f"/reports/{rid}/return", world.lead, json={"reason": "rework"}).status_code == 200
    )
    report = h.get(f"/reports/{rid}", world.lead).json()
    r = h.post(f"/reports/{rid}/submit", world.lead, json={"expected_revision": report["revision"]})
    assert r.status_code == 200, r.text
    r = h.post(f"/reports/{rid}/approve", world.lead)
    assert r.status_code == 403 and r.json()["error"]["details"]["rule"] == "four_eyes"
    r = h.post(f"/reports/{rid}/approve", world.lead2)
    assert r.status_code == 200 and r.json()["status"] == "approved"

    # sign
    r = h.post(f"/reports/{rid}/sign", world.lead)
    assert r.status_code == 200, r.text
    signed = r.json()
    assert signed["status"] == "signed" and signed["key_id"] == signer.key_id
    manifest = signed["manifest"]
    names = [a["name"] for a in manifest["artifacts"]]
    assert names == sorted(
        ["report.html", "report.pdf", "report.json", "iocs.stix.json", "iocs.csv", "timeline.csv"]
    )
    assert manifest["render_meta"]["approved_by"].startswith("Test lead")
    sign_audit = _audit(db_engine, "report.sign", rid)[0]
    assert sign_audit["manifest_sha256"] == signed["sha256"]
    assert set(sign_audit["artifacts"]) == set(names)
    assert world.patch(signed, user=world.lead, title="after").status_code == 409
    assert h.post(f"/reports/{rid}/sign", world.lead).status_code == 409

    # verify: ok, by an auditor too
    v = h.get(f"/reports/{rid}/verify", world.auditor)
    assert v.status_code == 200, v.text
    body = v.json()
    assert body["ok"] is True and body["signature_ok"] is True, body
    assert all(a["stored_ok"] and a["rerender_ok"] for a in body["artifacts"])

    # downloads: bytes match the manifest; safe headers
    by_name = {a["name"]: a for a in manifest["artifacts"]}
    fmt_names = {
        "html": "report.html",
        "pdf": "report.pdf",
        "json": "report.json",
        "stix": "iocs.stix.json",
        "csv": "iocs.csv",
        "timeline": "timeline.csv",
    }
    import hashlib

    for fmt, name in fmt_names.items():
        d = h.get(f"/reports/{rid}/download", world.viewer, params={"format": fmt})
        assert d.status_code == 200, (fmt, d.text)
        assert hashlib.sha256(d.content).hexdigest() == by_name[name]["sha256"]
        assert d.headers["x-content-sha256"] == by_name[name]["sha256"]
        assert "sandbox" in d.headers["content-security-policy"]
        assert d.headers["x-content-type-options"] == "nosniff"
        assert d.headers["content-disposition"].startswith("attachment")
    html = h.get(f"/reports/{rid}/preview", world.viewer)
    assert html.status_code == 200 and html.headers["content-disposition"].startswith("inline")
    page = html.text
    assert "<script" not in page.lower() and "<img" not in page.lower()
    assert "&lt;script&gt;" in page
    stix2.parse(h.get(f"/reports/{rid}/download", world.viewer, params={"format": "stix"}).text)
    timeline = h.get(f"/reports/{rid}/download", world.viewer, params={"format": "timeline"}).text
    assert "'=cmd|" in timeline
    assert (
        h.get(f"/reports/{rid}/download", world.viewer, params={"format": "custody"}).status_code
        == 422
    )

    # the seal verifies offline with the signer's public key only
    seal = h.get(f"/reports/{rid}/download", world.viewer, params={"format": "seal"}).json()
    offline = verify_report_seal(seal, Path("."), {signer.key_id: signer.public_key})
    assert offline["ok"] is True, offline
    other = CustodySigner(signer.key_id, Ed25519PrivateKey.generate())
    assert not verify_report_seal(seal, Path("."), {signer.key_id: other.public_key})["ok"]

    # tamper an artifact in storage: verify fails, the download refuses to serve it
    key = next(k for k in h.artifacts.objects if k.endswith("/report.pdf"))
    h.artifacts.objects[key] = h.artifacts.objects[key] + b"%tampered"
    body = h.get(f"/reports/{rid}/verify", world.lead).json()
    assert body["ok"] is False
    assert {p["code"] for p in body["problems"]} == {"artifact_mismatch"}
    d = h.get(f"/reports/{rid}/download", world.viewer, params={"format": "pdf"})
    assert d.status_code == 409 and d.json()["error"]["code"] == "artifact_tampered"
    assert _audit(db_engine, "report.verify", rid)[-1]["ok"] is False


def test_verify_trusts_only_keys_outside_the_database(
    world: World, db_engine: Engine, signer: CustodySigner
) -> None:
    signed = world.signed("executive")
    rid = signed["id"]
    h = world.h
    # An attacker with DB write access re-signs a changed manifest with their own key.
    attacker = CustodySigner(
        f"report-attacker-{uuid.uuid4().hex[:8]}", Ed25519PrivateKey.generate()
    )
    manifest = dict(signed["manifest"])
    manifest["key_id"] = attacker.key_id
    from app.reports.seal import manifest_sha256

    digest = manifest_sha256(manifest)
    with db_engine.begin() as conn:  # owner connection with triggers bypassed
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(
            text(
                "UPDATE reports SET manifest = CAST(:m AS jsonb), sha256 = :s, signature = :g, "
                "key_id = :k WHERE id = :i"
            ),
            {
                "m": json.dumps(manifest),
                "s": digest,
                "g": attacker.sign(digest),
                "k": attacker.key_id,
                "i": rid,
            },
        )
        conn.execute(
            text(
                "INSERT INTO signing_keys (key_id, algorithm, public_key, purpose) "
                "VALUES (:k, 'ed25519', :p, 'custody')"
            ),
            {"k": attacker.key_id, "p": attacker.public_key_pem()},
        )
    body = h.get(f"/reports/{rid}/verify", world.lead).json()
    assert body["ok"] is False and body["signature_ok"] is False
    assert "untrusted_key" in {p["code"] for p in body["problems"]}


def test_snapshot_edit_is_detected_by_verify(world: World, db_engine: Engine) -> None:
    signed = world.signed("executive")
    with db_engine.begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(
            text(
                "UPDATE reports SET context = jsonb_set(context, '{org}', '\"forged\"') "
                "WHERE id = :i"
            ),
            {"i": signed["id"]},
        )
    body = world.h.get(f"/reports/{signed['id']}/verify", world.lead).json()
    codes = {p["code"] for p in body["problems"]}
    assert body["ok"] is False and "context_mismatch" in codes and "rerender_mismatch" in codes


def test_render_limit_is_a_clean_413(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    h = world.h
    signed = world.signed("executive")
    report = world.fill(world.create("executive"))
    rid = report["id"]
    r = h.post(f"/reports/{rid}/submit", world.analyst, json={"expected_revision": 1})
    assert r.status_code == 200, r.text
    assert h.post(f"/reports/{rid}/approve", world.lead).status_code == 200
    budgets: list[object] = []

    def over_budget(*args: Any, time_budget_s: float | None = None, **kw: Any) -> Any:
        budgets.append(time_budget_s)
        raise RenderLimitError("the PDF did not render within 120 seconds")

    monkeypatch.setattr(report_service, "render_all", over_budget)
    monkeypatch.setattr(report_service, "render_one", over_budget)
    r = h.post(f"/reports/{rid}/sign", world.lead)
    assert r.status_code == 413 and r.json()["error"]["code"] == "report_too_large", r.text
    assert h.get(f"/reports/{rid}", world.viewer).json()["status"] == "approved"
    r = h.get(f"/reports/{rid}/download", world.viewer, params={"format": "pdf"})
    assert r.status_code == 413
    body = h.get(f"/reports/{signed['id']}/verify", world.lead).json()
    assert body["ok"] is False and {p["code"] for p in body["problems"]} == {"rerender_limit"}
    assert budgets and all(b == 120 for b in budgets)  # REPORT_RENDER_TIMEOUT_S default


def test_new_version_takes_a_fresh_snapshot(world: World, db_engine: Engine) -> None:
    signed = world.signed("technical")
    h = world.h
    r = h.post(
        f"/cases/{world.cid}/iocs",
        world.analyst,
        json={"type": "ip", "value": "203.0.113.9"},
    )
    assert r.status_code == 201
    r = h.post(f"/reports/{signed['id']}/versions", world.analyst)
    assert r.status_code == 201, r.text
    v2 = r.json()
    assert v2["version"] == 2 and v2["family_id"] == signed["family_id"]
    assert v2["supersedes_id"] == signed["id"] and v2["status"] == "draft"
    assert v2["context_sha256"] != signed["context_sha256"] and v2["counts"]["iocs"] == 2
    assert v2["findings"] == signed["findings"] and v2["sections"] == signed["sections"]
    listed = h.get(f"/cases/{world.cid}/reports", world.viewer).json()["items"]
    assert [x["version"] for x in listed][:2] == [2, 1]
    # the signed version is unchanged and still verifies
    assert h.get(f"/reports/{signed['id']}/verify", world.lead).json()["ok"] is True


# ---------------------------------------------------------------------------------- access


def test_rbac_and_case_isolation(world: World) -> None:
    h = world.h
    report = world.create()
    rid = report["id"]
    assert (
        h.post(f"/cases/{world.cid}/reports", world.viewer, json={"kind": "ioc"}).status_code == 403
    )
    assert h.get(f"/reports/{rid}", world.viewer).status_code == 200
    assert world.patch(report, user=world.viewer, title="x").status_code == 403
    assert h.get(f"/reports/{rid}/preview", world.viewer).status_code == 200
    assert h.get(f"/reports/{rid}/preview", world.auditor).status_code == 200
    for path in (
        f"/reports/{rid}",
        f"/reports/{rid}/preview",
        f"/reports/{rid}/download?format=pdf",
        f"/reports/{rid}/verify",
        f"/cases/{world.cid}/reports",
    ):
        assert h.get(path, world.outsider).status_code == 404, path
    for path in ("qa", "approve", "sign", "versions"):
        assert h.post(f"/reports/{rid}/{path}", world.outsider).status_code == 404, path
    assert (
        h.post(f"/cases/{world.cid}/reports", world.outsider, json={"kind": "ioc"}).status_code
        == 404
    )
    assert h.get(f"/reports/{uuid.uuid4()}", world.lead).status_code == 404
    # draft downloads are rendered now and marked as drafts
    d = h.get(f"/reports/{rid}/download", world.viewer, params={"format": "html"})
    assert d.status_code == 200 and "DRAFT - not approved" in d.text
    assert "_DRAFT_" in d.headers["content-disposition"]
    assert (
        h.get(f"/reports/{rid}/download", world.viewer, params={"format": "seal"}).status_code
        == 409
    )
    assert (
        h.post(f"/cases/{world.cid}/reports", world.analyst, json={"kind": "bogus"}).status_code
        == 422
    )


def test_closed_case_is_read_only(world: World) -> None:
    h = world.h
    signed = world.signed("executive")
    draft = world.create("technical")
    r = h.post(f"/cases/{world.cid}/close", world.lead, json={"reason": "done"})
    assert r.status_code == 200, r.text
    assert (
        h.post(f"/cases/{world.cid}/reports", world.analyst, json={"kind": "ioc"}).status_code
        == 409
    )
    assert world.patch(draft, title="x").status_code == 409
    assert h.post(f"/reports/{draft['id']}/qa", world.analyst).status_code == 409
    assert h.post(f"/reports/{signed['id']}/versions", world.analyst).status_code == 409
    assert h.get(f"/reports/{draft['id']}", world.viewer).status_code == 200
    assert h.get(f"/reports/{signed['id']}/verify", world.lead).json()["ok"] is True


# ---------------------------------------------------------------------------------- AI drafts


def test_ai_draft_needs_acceptance_and_is_labelled(world: World, db_engine: Engine) -> None:
    h = world.h
    report = world.create()
    rid = report["id"]
    r = h.post(f"/ai/reports/{rid}/draft", world.analyst, json={"section": "executive_summary"})
    assert r.status_code == 200, r.text
    out = r.json()
    iid = out["interaction"]["id"]
    assert out["interaction"]["status"] == "valid" and out["output"]["claims"]
    assert (
        h.post(f"/ai/reports/{rid}/draft", world.analyst, json={"section": "scope"}).status_code
        == 422
    )
    assert (
        h.post(f"/ai/reports/{rid}/draft", world.viewer, json={"section": "impact"}).status_code
        == 403
    )

    def apply(section: str, interaction: str, rev: int) -> Any:
        return h.post(
            f"/reports/{rid}/sections/{section}/apply-ai",
            world.analyst,
            json={"interaction_id": interaction, "expected_revision": rev},
        )

    r = apply("executive_summary", iid, 0)
    assert r.status_code == 409  # not accepted yet
    # a rejected draft can never be applied
    other = h.post(f"/ai/reports/{rid}/draft", world.analyst, json={"section": "impact"}).json()
    oid = other["interaction"]["id"]
    rv = h.post(f"/ai/interactions/{oid}/review", world.analyst, json={"decision": "reject"})
    assert rv.status_code == 200, rv.text
    assert apply("impact", oid, 0).status_code == 409
    # accepted, but for another section: not found
    rv = h.post(f"/ai/interactions/{iid}/review", world.lead, json={"decision": "accept"})
    assert rv.status_code == 200, rv.text
    assert apply("impact", iid, 0).status_code == 404
    # a non-draft interaction (alert explanation) cannot be applied
    ex = h.post(f"/ai/alerts/{world.alert_id}/explain", world.analyst).json()["interaction"]["id"]
    assert apply("executive_summary", ex, 0).status_code == 404
    r = apply("executive_summary", iid, 0)
    assert r.status_code == 200, r.text
    section = r.json()["sections"]["executive_summary"]
    assert section["origin"] == "ai_approved"
    assert section["ai"]["interaction_id"] == iid and section["ai"]["reviewed_by_label"].startswith(
        "Test lead"
    )
    assert section["ai"]["output_sha256"]
    page = h.get(f"/reports/{rid}/preview", world.viewer).text
    assert "AI-drafted, approved by Test lead" in page
    assert "No AI-drafted text is included" not in page
    # editing the AI text keeps the provenance but marks the edit
    r2 = world.patch(
        r.json(), sections={"executive_summary": section["text"] + "\n\nAnalyst note."}
    )
    assert r2.json()["sections"]["executive_summary"]["origin"] == "ai_edited"
    assert "edited by an analyst" in h.get(f"/reports/{rid}/preview", world.viewer).text
    assert _audit(db_engine, "report.apply_ai", rid)[0]["interaction_id"] == iid
    # QA flags AI content as a warning
    qa = h.post(f"/reports/{rid}/qa", world.analyst).json()["qa"]
    assert "ai_content" in {w["code"] for w in qa["warnings"]}


# ---------------------------------------------------------------------------------- other kinds


def test_custody_and_ioc_reports(world: World) -> None:
    h = world.h
    custody = world.signed("custody")
    names = {a["name"] for a in custody["manifest"]["artifacts"]}
    assert "custody.json" in names and "iocs.csv" not in names
    doc = h.get(
        f"/reports/{custody['id']}/download", world.auditor, params={"format": "custody"}
    ).json()
    assert doc["custody"][0]["ok"] is True and doc["custody"][0]["entries"]
    ioc = world.signed("ioc")
    assert {a["name"] for a in ioc["manifest"]["artifacts"]} == {
        "report.html",
        "report.json",
        "iocs.stix.json",
        "iocs.csv",
    }
    bundle = stix2.parse(
        h.get(f"/reports/{ioc['id']}/download", world.viewer, params={"format": "stix"}).text
    )
    assert any(o.type == "indicator" for o in bundle.objects)
    assert h.get(f"/reports/{ioc['id']}/verify", world.lead).json()["ok"] is True


def test_ioc_report_without_iocs_fails_qa(h: Harness) -> None:
    lead = h.make_user(UserRole.lead)
    cid = h.create_case(lead, "Empty")["id"]
    r = h.post(f"/cases/{cid}/reports", lead, json={"kind": "ioc"})
    assert r.status_code == 201, r.text
    report = r.json()
    r = h.patch(
        f"/reports/{report['id']}",
        lead,
        json={"expected_revision": 0, "sections": {"summary": "Nothing to share."}},
    )
    r = h.post(f"/reports/{report['id']}/submit", lead, json={"expected_revision": 1})
    assert r.status_code == 409
    assert "no_iocs" in {e["code"] for e in r.json()["error"]["details"]["errors"]}


# ---------------------------------------------------------------------------------- package


def test_evidence_export_package(world: World, db_engine: Engine, signer: CustodySigner) -> None:
    h = world.h
    eid = world.evidence["id"]
    r = h.post(f"/evidence/{eid}/export-package", world.analyst)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/zip"
    import hashlib

    digest = hashlib.sha256(r.content).hexdigest()
    assert r.headers["x-content-sha256"] == digest
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    assert sorted(zf.namelist()) == ["custody.json", "manifest.json", "manifest.sig"]
    manifest = json.loads(zf.read("manifest.json"))
    assert manifest["evidence"]["sha256"] == world.evidence["sha256"]
    assert manifest["original_included"] is False and manifest["processing_runs"]
    result = verify_package(r.content, {signer.key_id: signer.public_key})
    assert result["ok"] is True and result["custody_chain_ok"] is True, result
    chain = h.get(f"/evidence/{eid}/custody", world.analyst).json()
    last = chain["entries"][-1]
    assert last["action"] == "exported" and last["detail"]["package_sha256"] == digest
    assert [e["seq"] for e in chain["entries"]] == list(range(1, len(chain["entries"]) + 1))
    assert h.post(f"/evidence/{eid}/export-package", world.viewer).status_code == 403
    assert h.post(f"/evidence/{eid}/export-package", world.outsider).status_code == 404
    assert _audit(db_engine, "evidence.export_package", eid)[0]["package_sha256"] == digest


# ---------------------------------------------------------------------------------- database


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM reports",
        "TRUNCATE reports",
        "UPDATE reports SET context = '{}'::jsonb",
        "UPDATE reports SET context_sha256 = repeat('0', 64)",
        "UPDATE reports SET case_id = case_id",
        "UPDATE reports SET kind = 'ioc'",
        "UPDATE reports SET family_id = id",
        "UPDATE reports SET created_by = NULL",
    ],
)
def test_app_role_cannot_rewrite_reports(db_engine: Engine, statement: str) -> None:
    with db_engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("SET LOCAL ROLE dfirbench_app"))
        with pytest.raises(DBAPIError, match="permission denied"):
            conn.execute(text(statement))
        trans.rollback()


def test_report_guard_trigger(world: World, db_engine: Engine) -> None:
    signed = world.signed("executive")
    draft = world.create("ioc")

    def run(*statements: str, **params: Any) -> None:
        with db_engine.connect() as conn:
            trans = conn.begin()
            conn.execute(text("SET LOCAL ROLE dfirbench_app"))
            try:
                for sql in statements:
                    conn.execute(text(sql), params)
            finally:
                trans.rollback()

    with pytest.raises(DBAPIError, match="signed and cannot change"):
        run("UPDATE reports SET title = 'x' WHERE id = :i", i=signed["id"])
    with pytest.raises(DBAPIError, match="cannot move from draft to signed"):
        run("UPDATE reports SET status = 'signed' WHERE id = :i", i=draft["id"])
    with pytest.raises(DBAPIError, match="someone other than the submitter"):
        run(
            "UPDATE reports SET status = 'in_review', submitted_by = :u WHERE id = :i",
            "UPDATE reports SET status = 'approved', approved_by = :u WHERE id = :i",
            i=draft["id"],
            u=world.lead.id,
        )
    with pytest.raises(DBAPIError, match="only change in draft"):
        run(
            "UPDATE reports SET status = 'in_review' WHERE id = :i",
            "UPDATE reports SET sections = '{}'::jsonb WHERE id = :i",
            i=draft["id"],
        )
    with pytest.raises(DBAPIError, match="unreviewed draft"):
        run(
            "INSERT INTO reports (id, case_id, kind, version, status, context, family_id, "
            "context_sha256) VALUES (gen_random_uuid(), :c, 'ioc', 9, 'signed', '{}'::jsonb, "
            "gen_random_uuid(), repeat('0', 64))",
            c=world.cid,
        )
    with db_engine.connect() as conn:  # the seal CHECK holds even with triggers bypassed
        trans = conn.begin()
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        with pytest.raises(DBAPIError, match="signed_sealed"):
            conn.execute(
                text("UPDATE reports SET status = 'signed' WHERE id = :i"), {"i": draft["id"]}
            )
        trans.rollback()

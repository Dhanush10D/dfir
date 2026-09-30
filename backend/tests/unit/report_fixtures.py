"""A hand-made report snapshot with hostile evidence strings (shared by the report unit tests)."""

from __future__ import annotations

from typing import Any

from app.reports.model import default_sections

HOSTILE = '<script>alert("x")</script><img src=http://evil.example/x.png onerror=alert(1)>'
REPORT_ID = "11111111-1111-4111-8111-111111111111"
FAMILY_ID = REPORT_ID
EV1 = "22222222-2222-4222-8222-222222222222"
ALERT1 = "33333333-3333-4333-8333-333333333333"
EVENT1 = "44444444-4444-4444-8444-444444444444"
IOC1 = "55555555-5555-4555-8555-555555555555"


def sample_context(**overrides: Any) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "schema": 1,
        "generated_at": "2026-09-30T10:00:00Z",
        "generated_by": "Ana Analyst <ana@example.org>",
        "org": "dfirbench",
        "case": {
            "id": "66666666-6666-4666-8666-666666666666",
            "case_number": "IR-2026-0001",
            "title": "Intrusion " + HOSTILE,
            "description": "desc",
            "status": "open",
            "severity": "high",
            "classification": "confidential",
            "opened_at": "2026-09-01T00:00:00Z",
            "closed_at": None,
            "lead": "Lee Lead <lee@example.org>",
        },
        "evidence": [
            {
                "id": EV1,
                "label": "EV-001",
                "kind": "evtx",
                "original_name": "Security" + HOSTILE + ".evtx",
                "description": None,
                "source_host": "WS01",
                "size_bytes": 1024,
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "acquired_at": "2026-09-02T08:00:00Z",
                "acquired_by": "=cmd|' /C calc'!A0",
                "acquisition_tool": "KAPE 1.3",
                "acquisition_notes": None,
                "status": "stored",
                "parent_label": None,
                "received_at": "2026-09-02T09:00:00Z",
                "custody_ok": True,
                "custody_entries": 4,
            }
        ],
        "custody": [
            {
                "evidence_id": EV1,
                "label": "EV-001",
                "ok": True,
                "entries_total": 1,
                "head_hash": "c" * 64,
                "problems": [],
                "entries": [
                    {
                        "seq": 1,
                        "ts": "2026-09-02T09:00:00Z",
                        "actor": "Ana Analyst <ana@example.org>",
                        "action": "created",
                        "detail": '{"note":"' + HOSTILE + '"}',
                        "entry_hash": "c" * 64,
                        "key_id": "ed25519-test",
                    }
                ],
                "entries_truncated": False,
            }
        ],
        "alerts": [
            {
                "id": ALERT1,
                "title": "Suspicious " + HOSTILE,
                "rule_id": "WIN-0001",
                "severity": "high",
                "status": "new",
                "host": "WS01",
                "user": "bob",
                "attack": ["T1059.001"],
                "first_seen": "2026-09-02T07:00:00Z",
                "last_seen": "2026-09-02T07:05:00Z",
                "event_count": 3,
                "risk_score": "72.5",
            }
        ],
        "key_events": [
            {
                "id": EVENT1,
                "ts": "2026-09-02T07:00:00.123456Z",
                "ts_original": "2026-09-02 09:00:00.123456 +0200",
                "host": "WS01",
                "user": "bob",
                "source_type": "evtx",
                "event_code": "4688",
                "summary": "powershell -enc " + HOSTILE + " " + "A" * 300,
                "process_name": "powershell.exe",
                "cmdline": '=HYPERLINK("http://evil")',
                "file_path": None,
                "src_ip": None,
                "dst_ip": "203.0.113.5",
                "evidence_id": EV1,
                "evidence_label": "EV-001",
                "reasons": ["alert", "bookmark"],
            }
        ],
        "iocs": [
            {
                "id": IOC1,
                "type": "domain",
                "value": "evil.example",
                "source": "analyst",
                "tlp": "amber",
                "confidence": "0.8",
                "first_seen": "2026-09-02T07:00:00Z",
                "active": True,
                "global": False,
            },
            {
                "id": "77777777-7777-4777-8777-777777777777",
                "type": "filename",
                "value": 'it\'s \\ "bad".exe',
                "source": "@SUM(1)",
                "tlp": "amber+strict",
                "confidence": "0.5",
                "first_seen": None,
                "active": True,
                "global": True,
            },
            {
                "id": "88888888-8888-4888-8888-888888888888",
                "type": "sha256",
                "value": "d" * 64,
                "source": "misp",
                "tlp": "green",
                "confidence": None,
                "first_seen": None,
                "active": True,
                "global": False,
            },
        ],
        "attack": [{"technique": "T1059.001", "alerts": 1, "events": 3}],
        "entities": [],
        "runs": [
            {
                "job_id": "99999999-9999-4999-8999-999999999999",
                "kind": "parse",
                "parser": "evtx",
                "parser_version": "1.0.0",
                "outcome": "succeeded",
                "evidence_label": "EV-001",
                "finished_at": "2026-09-02T09:10:00Z",
                "records_read": 10,
                "events_emitted": 10,
                "tools": "dfirbench=0.1.0; python=3.12.0",
            }
        ],
        "ai_outputs": [],
        "counts": {
            "evidence": 1,
            "events": 10,
            "alerts": 1,
            "alerts_by_severity": {"high": 1},
            "iocs": 3,
            "key_events": 1,
            "custody_ok": 1,
            "runs": 1,
        },
        "truncated": {"key_events": False, "alerts": False, "iocs": False, "runs": False},
        "input_hashes": {"evidence": "e" * 64, "alerts": "f" * 64},
    }
    ctx.update(overrides)
    return ctx


def sample_meta(kind: str = "technical", **overrides: Any) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "report_id": REPORT_ID,
        "family_id": FAMILY_ID,
        "version": 1,
        "kind": kind,
        "title": "Report " + HOSTILE,
        "status": "signed",
        "status_label": "Signed",
        "author": "Ana Analyst <ana@example.org>",
        "approved_by": "Lee Lead <lee@example.org>",
        "approved_at": "2026-09-30T11:00:00Z",
        "signed_by": "Lee Lead <lee@example.org>",
        "signed_at": "2026-09-30T11:05:00Z",
        "key_id": "ed25519-test",
        "context_sha256": "1" * 64,
        "content_sha256": "2" * 64,
    }
    meta.update(overrides)
    return meta


def sample_sections(kind: str = "technical") -> dict[str, Any]:
    sections = default_sections(kind)
    for name in sections:
        if not sections[name]["text"]:
            sections[name] = {"text": f"Text for {name}. " + HOSTILE, "origin": "analyst"}
    return sections


def sample_findings() -> list[dict[str, Any]]:
    return [
        {
            "id": "f-1",
            "title": "Encoded PowerShell " + HOSTILE,
            "body": "The attacker ran **encoded** PowerShell. [link](javascript:alert(1))",
            "confidence": "high",
            "attack": ["T1059.001"],
            "origin": "analyst",
            "refs": [
                {
                    "type": "event",
                    "id": EVENT1,
                    "label": "4688 on WS01",
                    "ts": "2026-09-02T07:00:00.123456Z",
                    "summary": HOSTILE,
                }
            ],
        }
    ]

"""Event payloads and notification messages (guide 15.6, 19.3, 19.4). Pure.

Payloads carry identifiers, enumerated values and counts only. Text that comes from evidence
(an alert title, a host name, an evidence label) lives under ``details`` and is left out unless a
channel is configured with ``include_details``; it is never used as a template, only inserted as
a value after control characters are removed and the target's markup is escaped. Messages are
built from the constant strings below: there is no template engine and no format string that
could come from data.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

EVENT_ALERT_CREATED = "alert.created"
EVENT_CASE_STATUS = "case.status_changed"
EVENT_REPORT_SIGNED = "report.signed"
EVENT_EVIDENCE_FAILED = "evidence.verification_failed"
EVENT_RUN_STARTED = "playbook.run_started"
EVENT_APPROVAL_REQUESTED = "playbook.approval_requested"
EVENT_PLAYBOOK_NOTICE = "playbook.notice"
# Sent only to the one integration an admin tests (never subscribable).
EVENT_TEST = "integration.test"

GUIDE_EVENTS = (
    EVENT_ALERT_CREATED,
    EVENT_CASE_STATUS,
    EVENT_REPORT_SIGNED,
    EVENT_EVIDENCE_FAILED,
)
# What a channel can subscribe to.
SUBSCRIBABLE_EVENTS = (
    *GUIDE_EVENTS,
    EVENT_RUN_STARTED,
    EVENT_APPROVAL_REQUESTED,
    EVENT_PLAYBOOK_NOTICE,
)
EVENT_TYPES = (*SUBSCRIBABLE_EVENTS, EVENT_TEST)

SEVERITIES = ("info", "low", "medium", "high", "critical")
CASE_NUMBER_RE = re.compile(r"^[A-Z]{2,8}-[A-Z0-9]{2,8}-[A-Za-z0-9]{1,12}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:+-]{1,80}$")
# Line/paragraph separators and bidirectional overrides (built with chr(): no literal
# invisible characters in this file).
_INVISIBLE = "".join(
    chr(c) for c in (0x2028, 0x2029, *range(0x202A, 0x202F), *range(0x2066, 0x206A))
)
CONTROL_RE = re.compile(
    "[" + chr(0) + "-" + chr(0x1F) + chr(0x7F) + "-" + chr(0x9F) + _INVISIBLE + "]"
)
MAX_DETAIL_CHARS = 200
MAX_LIST = 20

TITLES: dict[str, str] = {
    EVENT_ALERT_CREATED: "New alert",
    EVENT_CASE_STATUS: "Case status changed",
    EVENT_REPORT_SIGNED: "Report signed",
    EVENT_EVIDENCE_FAILED: "Evidence verification failed",
    EVENT_RUN_STARTED: "Playbook started",
    EVENT_APPROVAL_REQUESTED: "Approval requested",
    EVENT_PLAYBOOK_NOTICE: "Playbook step notice",
    EVENT_TEST: "Test notification",
}
# Field -> label, per event, in display order. Only these payload fields are ever rendered.
FIELDS: dict[str, tuple[tuple[str, str], ...]] = {
    EVENT_ALERT_CREATED: (
        ("severity", "Severity"),
        ("rule_id", "Rule"),
        ("source", "Source"),
        ("event_count", "Events"),
        ("alert_id", "Alert"),
    ),
    EVENT_CASE_STATUS: (("from_status", "From"), ("to_status", "To")),
    EVENT_REPORT_SIGNED: (
        ("kind", "Kind"),
        ("version", "Version"),
        ("report_id", "Report"),
        ("manifest_sha256", "Manifest SHA-256"),
    ),
    EVENT_EVIDENCE_FAILED: (("stage", "Stage"), ("evidence_id", "Evidence")),
    EVENT_RUN_STARTED: (("playbook_id", "Playbook"), ("run_id", "Run")),
    EVENT_APPROVAL_REQUESTED: (
        ("action", "Action"),
        ("playbook_id", "Playbook"),
        ("step_key", "Step"),
        ("request_id", "Request"),
        ("expires_at", "Expires"),
    ),
    EVENT_PLAYBOOK_NOTICE: (("playbook_id", "Playbook"), ("step_key", "Step"), ("run_id", "Run")),
    EVENT_TEST: (("integration", "Integration"),),
}
# Evidence-derived fields (shown only with ``include_details``).
DETAIL_FIELDS: dict[str, tuple[tuple[str, str], ...]] = {
    EVENT_ALERT_CREATED: (("title", "Title"), ("host", "Host")),
    EVENT_EVIDENCE_FAILED: (("label", "Label"),),
}
TABS: dict[str, str] = {
    EVENT_ALERT_CREATED: "alerts",
    EVENT_CASE_STATUS: "overview",
    EVENT_REPORT_SIGNED: "reports",
    EVENT_EVIDENCE_FAILED: "evidence",
    EVENT_RUN_STARTED: "response",
    EVENT_APPROVAL_REQUESTED: "response",
    EVENT_PLAYBOOK_NOTICE: "response",
    EVENT_TEST: "overview",
}


def plain(value: object, limit: int = MAX_DETAIL_CHARS) -> str:
    """One line of text without control or bidirectional-override characters, bounded."""
    text = " ".join(CONTROL_RE.sub(" ", str(value)).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _token(value: object) -> str | None:
    """A value from the closed vocabulary (ids, enum names, numbers), or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and TOKEN_RE.fullmatch(value):
        return value
    return None


def _uuid(value: object) -> str | None:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return None


@dataclass(frozen=True)
class Message:
    """A rendered notification, still target-neutral (values are plain text, not escaped)."""

    event: str
    title: str
    lines: tuple[tuple[str, str], ...]  # (label, value)
    link: str | None


def details_of(payload: Mapping[str, Any]) -> dict[str, str]:
    raw = payload.get("details")
    if not isinstance(raw, Mapping):
        return {}
    return {str(k)[:32]: plain(v) for k, v in list(raw.items())[:MAX_LIST] if v is not None}


def public_payload(payload: Mapping[str, Any], *, include_details: bool) -> dict[str, Any]:
    """The payload as sent to a receiver (``details`` only when the channel opted in)."""
    out = {k: v for k, v in payload.items() if k != "details"}
    if include_details:
        details = details_of(payload)
        if details:
            out["details"] = details
    return out


def build_message(
    payload: Mapping[str, Any], *, include_details: bool = False, base_url: str | None = None
) -> Message:
    event = str(payload.get("event") or "")
    if event not in EVENT_TYPES:
        raise ValueError("unknown event type")
    case_number = payload.get("case_number")
    title = TITLES[event]
    if isinstance(case_number, str) and CASE_NUMBER_RE.fullmatch(case_number):
        title = f"{title} in case {case_number}"
    lines: list[tuple[str, str]] = []
    for name, label in FIELDS[event]:
        value = _token(payload.get(name))
        if value is not None:
            lines.append((label, value))
    attack = payload.get("attack")
    if isinstance(attack, list):
        techniques = [t for t in (_token(x) for x in attack[:MAX_LIST]) if t]
        if techniques:
            lines.append(("ATT&CK", ", ".join(techniques)))
    if include_details:
        details = details_of(payload)
        for name, label in DETAIL_FIELDS.get(event, ()):
            if details.get(name):
                lines.append((label, details[name]))
    link = None
    case_id = _uuid(payload.get("case_id"))
    if base_url and case_id:
        link = f"{base_url.rstrip('/')}/cases/{case_id}/{TABS[event]}"
    return Message(event=event, title=title, lines=tuple(lines), link=link)


# ------------------------------------------------------------------------------ targets


def escape_slack(text: str) -> str:
    """Slack control characters (``& < >``); markup is also switched off in the payload."""
    return plain(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_TEAMS_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-!|>~<&@])")


def escape_teams(text: str) -> str:
    """Backslash-escape the Markdown subset an Adaptive Card TextBlock renders."""
    return _TEAMS_SPECIAL.sub(r"\\\1", plain(text))


def render_slack(message: Message) -> bytes:
    rows = [escape_slack(message.title)]
    rows += [f"{escape_slack(label)}: {escape_slack(value)}" for label, value in message.lines]
    if message.link:
        rows.append(escape_slack(message.link))
    return json.dumps({"text": "\n".join(rows), "mrkdwn": False}).encode("utf-8")


def render_teams(message: Message) -> bytes:
    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "text": escape_teams(message.title), "weight": "Bolder", "wrap": True}
    ]
    body += [
        {"type": "TextBlock", "text": f"{escape_teams(label)}: {escape_teams(value)}", "wrap": True}
        for label, value in message.lines
    ]
    card: dict[str, Any] = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    if message.link:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open case", "url": message.link}]
    payload = {
        "type": "message",
        "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}
        ],
    }
    return json.dumps(payload).encode("utf-8")


def render_email(message: Message) -> tuple[str, str]:
    """(subject, plain-text body). The mailer also strips CR/LF from every header."""
    subject = plain(f"[dfirbench] {message.title}", 150)
    rows = [message.title, ""]
    rows += [f"{label}: {plain(value)}" for label, value in message.lines]
    if message.link:
        rows += ["", message.link]
    rows += ["", "Open the case in dfirbench for details."]
    return subject, "\n".join(rows) + "\n"


def render_webhook(
    event_id: object, created_at: str, payload: Mapping[str, Any], *, include_details: bool
) -> bytes:
    """Canonical JSON body of an outbound webhook (the bytes that are signed)."""
    body = {
        "id": str(event_id),
        "type": str(payload.get("event")),
        "created_at": created_at,
        "data": public_payload(payload, include_details=include_details),
    }
    return json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode()


def in_app_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """What an in-app notification stores: identifiers and enumerated values only."""
    message = build_message(payload)
    return {
        "event": message.event,
        "title": message.title,
        "case_id": _uuid(payload.get("case_id")),
        "tab": TABS[message.event],
        "fields": [{"label": label, "value": value} for label, value in message.lines],
    }

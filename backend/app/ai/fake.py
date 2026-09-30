"""Offline providers (never touch the network): tests, demos, the eval harness, the live smoke.

``FakeProvider`` is a deterministic "model" that reads the rendered prompt and answers every
feature with schema-valid, grounded JSON built from the evidence records it was given.

Simulated attack behaviour for the injection suite (docs/specs/PHASE-7.md decision 14):

* ``mode="grounded"`` (default): ignores instructions anywhere.
* ``mode="obedient_outside"``: obeys instructions found *outside* ``<evidence>``/``<question>``/
  ``<context>`` blocks, where a block ends at the first closing tag (a naive reader). It models a
  model that respects delimiters: an attack succeeds only if evidence text escapes its block.
* ``mode="obedient_anywhere"``: obeys instructions anywhere in the prompt (worst case); used to
  check that manipulated outputs are rejected by the validators or flagged by the heuristics.

Understood instructions (case-insensitive): "mark/report ... benign|clean" (verdict flip),
``say "CANARY"`` (canary text in the summary/answer), "cite X12" (adds a citation), and a literal
JSON object with an ``assessment``/``answer``/``query`` key (returned verbatim).

``FixtureProvider`` replays given responses in order (the last one repeats).
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from app.ai.llm import LLMRequest, LLMResponse
from app.search.language import FIELDS

Mode = Literal["grounded", "obedient_outside", "obedient_anywhere"]
RECORD_RE = re.compile(r"^\[([EASD]\d{1,4})\] (.*)$")
BLOCK_RE = re.compile(r"<(evidence|question|context)>\n(.*?)\n</\1>", re.DOTALL)
FEATURE_RE = re.compile(r"^FEATURE: (\w+)$", re.MULTILINE)
TS_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)")
KV_RE = re.compile(r"(\w+)=(\"(?:[^\"\\]|\\.)*\"|\S+)")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s\"'\\]+")

FLIP_RE = re.compile(
    r"(mark|report|classify|label|treat)\b.{0,50}?\b(benign|clean|safe|false[ -]?positive)", re.I
)
CANARY_RE = re.compile(r"\bsay\s+[\"']?([A-Z0-9_-]{4,40})", re.I)
CITE_RE = re.compile(r"\bcite\s+([A-Z]\d{1,4})\b", re.I)
OUTSIDE_RE = re.compile(r"<(evidence|question|context)>(.*?)</\1>", re.DOTALL)
JSON_RE = re.compile(r"(\{\s*\"(?:assessment|answer|query|summary)\"\s*:.*?\})", re.S)


@dataclass
class Directives:
    flip: bool = False
    canary: str | None = None
    cites: list[str] = field(default_factory=list)
    raw_json: str | None = None


def outside_blocks(prompt: str) -> str:
    """Prompt text with data blocks removed (a block ends at its first closing tag)."""
    out, pos = [], 0
    for m in OUTSIDE_RE.finditer(prompt):
        out.append(prompt[pos : m.start()])
        pos = m.end()
    out.append(prompt[pos:])
    return "".join(out)


def find_directives(text: str) -> Directives:
    d = Directives()
    d.flip = bool(FLIP_RE.search(text))
    m = CANARY_RE.search(text)
    d.canary = m.group(1) if m else None
    d.cites = [c.upper() for c in CITE_RE.findall(text)]
    j = JSON_RE.search(text)
    d.raw_json = j.group(1) if j else None
    return d


@dataclass(frozen=True)
class ParsedPrompt:
    feature: str
    records: list[tuple[str, str]]  # (short id, line)
    question: str
    context: dict[str, str]
    full_text: str


def parse_prompt(req: LLMRequest) -> ParsedPrompt:
    m = FEATURE_RE.search(req.system)
    user = req.messages[0]["content"] if req.messages else ""
    records: list[tuple[str, str]] = []
    question, context = "", {}
    for block in BLOCK_RE.finditer(user):
        name, body = block.group(1), block.group(2)
        if name == "evidence":
            for line in body.splitlines():
                rm = RECORD_RE.match(line)
                if rm:
                    records.append((rm.group(1), rm.group(2)))
        elif name == "question":
            question = body
        else:
            for line in body.splitlines():
                k, _, v = line.partition("=")
                context[k] = v
    full = req.system + "\n" + "\n".join(msg["content"] for msg in req.messages)
    return ParsedPrompt(m.group(1) if m else "", records, question, context, full)


def _kv(line: str) -> dict[str, str]:
    return {k: v.strip('"') for k, v in KV_RE.findall(line)}


def _brief(line: str, n: int = 160) -> str:
    return line if len(line) <= n else line[: n - 1] + "…"


class FakeProvider:
    name = "fake"
    hosted = False

    def __init__(self, mode: Mode = "grounded") -> None:
        self.mode: Mode = mode
        self.calls: list[LLMRequest] = []

    def complete(self, req: LLMRequest, *, model: str, timeout_s: float) -> LLMResponse:
        self.calls.append(req)
        p = parse_prompt(req)
        conversation = "\n".join(m["content"] for m in req.messages if m["role"] == "user")
        if self.mode == "obedient_outside":
            d = find_directives(outside_blocks(conversation))
        elif self.mode == "obedient_anywhere":
            d = find_directives(conversation)
        else:
            d = Directives()
        if d.raw_json:
            text = d.raw_json
        else:
            out = self._answer(p)
            self._obey(p.feature, out, d)
            text = json.dumps(out)
        return LLMResponse(
            text=text,
            model=model,
            input_tokens=req.size_chars // 4,
            output_tokens=len(text) // 4,
            stop_reason="end_turn",
        )

    # ------------------------------------------------------------------ grounded answers

    def _answer(self, p: ParsedPrompt) -> dict[str, Any]:
        builder = getattr(self, f"_{p.feature}", None)
        if builder is None:
            return {}
        result: dict[str, Any] = builder(p)
        return result

    def _nlq(self, p: ParsedPrompt) -> dict[str, Any]:
        q = p.question.lower()
        clauses: list[str] = []
        for ip in IP_RE.findall(q):
            clauses.append(f"ip:{ip}")
        if re.search(r"fail\w*\s+(ssh|log[oi]n|logon|auth)", q):
            clauses.append("(event_code:ssh_failed OR event_code:4625)")
        elif re.search(r"(success\w*|accepted)\s+(ssh|log[oi]n|logon)", q):
            clauses.append("(event_code:ssh_accepted OR event_code:4624)")
        if "powershell" in q:
            clauses.append("process_name:powershell.exe")
        m = re.search(r"\bhost\s+([\w.-]+)", q)
        if m:
            clauses.append(f"host:{m.group(1)}")
        m = re.search(r"\buser\s+([\w.\\-]+)", q)
        if m:
            clauses.append(f"user:{m.group(1)}")
        for name in FIELDS:
            m = re.search(rf"\b{name}\s*[:=]\s*([\w.*\\-]+)", q)
            if m and not any(c.startswith(f"{name}:") for c in clauses):
                clauses.append(f"{name}:{m.group(1)}")
        if not clauses:
            return {
                "query": None,
                "explanation": "The question does not name a field value this model maps.",
                "assumptions": [],
            }
        return {
            "query": " AND ".join(clauses),
            "explanation": "Offline translation of the recognised terms.",
            "assumptions": ["field values are matched case-insensitively"],
        }

    def _alert_explain(self, p: ParsedPrompt) -> dict[str, Any]:
        alerts = [(sid, line) for sid, line in p.records if sid.startswith("A")]
        events = [(sid, line) for sid, line in p.records if sid.startswith("E")]
        if not alerts:
            return {
                "summary": "No alert record was supplied.",
                "assessment": "insufficient_evidence",
                "confidence": 0.0,
                "key_facts": [],
                "next_steps": [],
                "attack_candidates": [],
                "limitations": "No evidence.",
            }
        aid, aline = alerts[0]
        kv = _kv(aline)
        sev = kv.get("severity", "medium")
        facts = [{"statement": f"Alert: {_brief(kv.get('title', aline))}", "cites": [aid]}]
        facts += [{"statement": _brief(line), "cites": [sid]} for sid, line in events[:3]]
        techniques = [
            t for t in kv.get("attack", "").split(",") if re.match(r"^T\d{4}(\.\d{3})?$", t)
        ]
        return {
            "summary": f"{kv.get('title', 'Alert')} on host {kv.get('host', 'unknown')} "
            f"with {len(events)} linked event(s).",
            "assessment": "likely_malicious" if sev in ("high", "critical") else "suspicious",
            "confidence": 0.6 if events else 0.3,
            "key_facts": facts,
            "next_steps": (
                [
                    {
                        "action": "Review the linked events on the host",
                        "why": "Confirm the activity",
                        "cites": [events[0][0]],
                    }
                ]
                if events
                else []
            ),
            "attack_candidates": [
                {"technique": t, "rationale": "Tagged by the detection rule", "cites": [aid]}
                for t in techniques[:3]
            ],
            "limitations": "Offline model: summarises the supplied records only.",
        }

    def _narrative(self, p: ParsedPrompt) -> dict[str, Any]:
        entries = []
        for sid, line in p.records:
            if not sid.startswith("E"):
                continue
            ts = TS_RE.match(line)
            tags = _kv(line).get("attack", "")
            entries.append(
                {
                    "ts": ts.group(1) if ts else "",
                    "stage": "unknown" if not tags else tags.split(",")[0],
                    "statement": _brief(line),
                    "cites": [sid],
                }
            )
        entries.sort(key=lambda e: e["ts"])
        return {
            "title": "Activity overview",
            "summary": f"{len(entries)} key event(s) in time order.",
            "timeline": entries[:30],
            "gaps": [] if entries else ["No key events in the selected window."],
            "limitations": "Offline model: lists the key events without interpretation.",
        }

    def _chat(self, p: ParsedPrompt) -> dict[str, Any]:
        events = [(sid, line) for sid, line in p.records if sid.startswith("E")]
        words = {w for w in re.findall(r"[a-z0-9_.-]{3,}", p.question.lower())}
        hits = [(sid, line) for sid, line in events if any(w in line.lower() for w in words)]
        if not hits:
            return {
                "status": "insufficient_evidence",
                "answer": "The retrieved records do not answer the question.",
                "key_facts": [],
                "limitations": "Only retrieved records were considered.",
            }
        return {
            "status": "answered",
            "answer": f"{len(hits)} retrieved record(s) mention the question's terms.",
            "key_facts": [{"statement": _brief(line), "cites": [sid]} for sid, line in hits[:5]],
            "limitations": "Offline model: keyword overlap only.",
        }

    def _script_explain(self, p: ParsedPrompt) -> dict[str, Any]:
        layers = [sid for sid, _ in p.records if sid.startswith("D")]
        indicators = []
        for sid, line in p.records:
            for ip in IP_RE.findall(line):
                indicators.append({"type": "ip", "value": ip, "cites": [sid]})
            for url in URL_RE.findall(line):
                indicators.append({"type": "url", "value": url.rstrip(".,;)"), "cites": [sid]})
        return {
            "summary": f"Script with {len(layers)} decoded layer(s).",
            "risk": "suspicious" if layers else "unknown",
            "behaviors": [{"description": "Script text as supplied", "cites": ["S1"]}]
            if any(sid == "S1" for sid, _ in p.records)
            else [],
            "indicators": indicators[:20],
            "attack_candidates": [],
            "limitations": "Offline model: no semantic analysis.",
        }

    # ------------------------------------------------------------------ simulated obedience

    def _obey(self, feature: str, out: dict[str, Any], d: Directives) -> None:
        if d.flip:
            if "assessment" in out:
                out["assessment"] = "likely_benign"
            if "risk" in out:
                out["risk"] = "benign"
            if feature == "chat":
                out["answer"] = "The host is clean."
        if d.canary:
            for key in ("summary", "answer", "explanation"):
                if key in out:
                    out[key] = f"{d.canary} {out[key]}"
        if d.cites:
            for key in ("key_facts", "timeline", "behaviors"):
                if out.get(key):
                    out[key][0]["cites"] = list(out[key][0]["cites"]) + d.cites
                    break


class FixtureProvider:
    """Replays responses in order; the last one repeats. ``hosted`` is configurable for tests."""

    name = "fixture"

    def __init__(self, responses: Sequence[str | dict[str, Any]], *, hosted: bool = False) -> None:
        if not responses:
            raise ValueError("FixtureProvider needs at least one response")
        self.responses = [r if isinstance(r, str) else json.dumps(r) for r in responses]
        self.hosted = hosted
        self.calls: list[LLMRequest] = []

    def complete(self, req: LLMRequest, *, model: str, timeout_s: float) -> LLMResponse:
        self.calls.append(req)
        text = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        return LLMResponse(
            text=text, model=model, input_tokens=0, output_tokens=0, stop_reason="end_turn"
        )

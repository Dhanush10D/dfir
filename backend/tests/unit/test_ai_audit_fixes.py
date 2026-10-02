"""Regression tests for AI-layer audit findings: draft text checked against evidence, strict
redaction of context and hidden secrets, quoting that cannot forge fields, whole-token claim
support, a refused corrective retry keeping the first call, and numeric single-label hosts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.ai.features import SPECS, events_pack, narrative_pack
from app.ai.gateway import Gateway, GatewayConfig, MemoryRateLimiter, is_local_url
from app.ai.llm import LLMResponse
from app.ai.packs import _value
from app.ai.runner import FeatureRunner
from app.ai.validators import check_citations

TS = datetime(2026, 1, 1, tzinfo=UTC)


def test_report_draft_text_is_checked_against_the_evidence() -> None:
    data = {
        "text": "Data went to 203.0.113.99 via https://evil.example/x",
        "claims": [{"statement": "WS1 had a login", "cites": ["E1"]}],
    }
    report = check_citations(data, {"E1": "host=WS1 src_ip=10.0.0.5"}, required=("claims",))
    paths = {u["path"] for u in report.unsupported}
    assert "text" in paths


def test_claims_need_whole_tokens_not_substrings() -> None:
    data = {"claims": [{"statement": "login from 10.0.0.5", "cites": ["E1"]}]}
    report = check_citations(data, {"E1": "src_ip=10.0.0.55"}, required=("claims",))
    assert report.unsupported
    ok = check_citations(data, {"E1": "src_ip=10.0.0.5"}, required=("claims",))
    assert not ok.unsupported


def test_quoted_values_cannot_forge_fields() -> None:
    forged = _value('powershell.exe -c x\\" user=SYSTEM host=DC01', 300)
    assert forged == '"powershell.exe -c x\\\\\\" user=SYSTEM host=DC01"'
    assert _value("C:\\Program Files\\x.exe", 300) == '"C:\\Program Files\\x.exe"'
    assert _value("CORP\\alice", 300) == "CORP\\alice"


class _EchoGateway:
    provider_name = "p"
    hosted = True

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def model_for(self, tier: str) -> str:
        return "m"

    def complete(self, req: Any, *, user_key: str, case_key: str) -> tuple[LLMResponse, Any]:
        self.prompts.append(req.messages[0]["content"])

        class Stats:
            latency_ms = 1

        return LLMResponse(text="{}", model="m"), Stats()


def test_strict_redaction_covers_context_and_hidden_secrets() -> None:
    full_width = "".join(chr(ord(c) + 0xFEE0) for c in "password=")
    message = f"login from 10.1.2.3 pass\u200bword=hunter2 {full_width}S3cr3t!"
    ev = {"id": "1", "ts": TS, "host": "WS-FIN-01", "user": "alice", "message": message}
    pack = narrative_pack([], [ev], max_records=10, max_field_chars=500)
    gw = _EchoGateway()
    FeatureRunner(gw, redaction_policy="strict", redact_local=False, max_tokens=100).run(  # type: ignore[arg-type]
        SPECS["narrative"],
        pack,
        user_key="u",
        case_key="c",
        context={"start": "(case start)", "end": "(case end)", "host": "WS-FIN-01"},
    )
    prompt = gw.prompts[0]
    assert "WS-FIN-01" not in prompt
    assert "hunter2" not in prompt and "S3cr3t!" not in prompt


class _Provider:
    name = "p"
    hosted = True
    calls = 0

    def complete(self, req: Any, *, model: str, timeout_s: float) -> LLMResponse:
        _Provider.calls += 1
        text = (
            '{"status":"answered","answer":"x","key_facts":[{"statement":"s","cites":["E99"]}],'
            '"limitations":""}'
        )
        return LLMResponse(text=text, model="m", input_tokens=500, output_tokens=90)


def test_refused_corrective_retry_keeps_the_first_call() -> None:
    cfg = GatewayConfig(
        enabled=True,
        local_only=False,
        model_fast="f",
        model_strong="s",
        max_input_chars=10**6,
        timeout_s=5,
        max_retries=0,
        embedding_model="e",
    )
    gateway = Gateway(_Provider(), cfg, MemoryRateLimiter(1, 100))  # one call per minute
    events = [{"id": "1", "ts": TS, "host": "h", "message": "m"}]
    pack = events_pack(events, max_records=10, max_field_chars=500)
    runner = FeatureRunner(
        gateway, redaction_policy="standard", redact_local=False, max_tokens=1000
    )
    out = runner.run(SPECS["chat"], pack, user_key="u", case_key="c", question="q")
    assert out.status == "invalid" and out.attempts == 1
    assert out.input_tokens == 500 and any("corrective retry" in p for p in out.problems)


def test_numeric_single_label_hosts_are_not_local() -> None:
    assert is_local_url("http://ollama:11434")
    assert not is_local_url("http://134744072:11434")
    assert not is_local_url("http://0x08080808/")

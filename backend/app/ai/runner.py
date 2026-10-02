"""Feature runner (guide 13.3 steps 3-5): render -> redact -> gateway -> validate -> (retry once).

Pure orchestration over a :class:`~app.ai.gateway.Gateway`-like object: no database access, so
the same code runs in the API service and in the offline eval harness.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic import BaseModel

from app.ai.llm import LLMRequest, LLMResponse
from app.ai.packs import EvidencePack
from app.ai.prompts import TEMPLATES, render_user
from app.ai.redaction import Policy, Redactor
from app.ai.schemas import provider_schema
from app.ai.validators import CitationReport, check_citations, parse_output
from app.core.exceptions import AppError

MAX_PROMPT_TEXT = 256 * 1024
MAX_ECHO = 8000  # characters of a rejected reply echoed back in the corrective turn


class GatewayLike(Protocol):
    @property
    def provider_name(self) -> str: ...

    @property
    def hosted(self) -> bool: ...

    def model_for(self, tier: str) -> str: ...

    def complete(self, req: LLMRequest, *, user_key: str, case_key: str | None) -> Any: ...


@dataclass(frozen=True)
class FeatureSpec:
    feature: str
    output: type[BaseModel]
    required_cites: tuple[str, ...] = ()  # list fields whose items must cite
    indicator_lists: tuple[str, ...] = ()
    # Extra checks on the parsed output (e.g. the NL query must parse); returns problems.
    extra_check: Callable[[BaseModel], list[str]] | None = None


@dataclass
class RunOutcome:
    status: str  # valid | invalid | refused
    output: dict[str, Any]
    parsed: BaseModel | None
    problems: list[str]
    warnings: list[dict[str, Any]]
    citations: CitationReport | None
    response: LLMResponse | None
    model_requested: str
    latency_ms: int = 0
    attempts: int = 0
    prompt_text: str = ""
    prompt_sha256: str = ""
    output_sha256: str = ""
    input_sha256: str = ""
    prompt_version: str = ""
    redactions: dict[str, Any] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


class FeatureRunner:
    def __init__(
        self,
        gateway: GatewayLike,
        *,
        redaction_policy: Policy,
        redact_local: bool,
        max_tokens: int,
        max_question_chars: int = 2000,
    ) -> None:
        self.gateway = gateway
        self.redaction_policy: Policy = redaction_policy
        self.redact_local = redact_local
        self.max_tokens = max_tokens
        self.max_question_chars = max_question_chars

    def _redactor(self) -> Redactor:
        use = self.gateway.hosted or self.redact_local
        return Redactor(self.redaction_policy if use else "none")

    def run(
        self,
        spec: FeatureSpec,
        pack: EvidencePack | None,
        *,
        user_key: str,
        case_key: str | None,
        question: str | None = None,
        context: dict[str, str] | None = None,
    ) -> RunOutcome:
        template = TEMPLATES[spec.feature]
        redactor = self._redactor()
        # Redaction runs on RAW values (evidence fields, question, context) before they are
        # sanitized, quoted and truncated, never on the rendered text.
        redact = redactor.redact_value if redactor.policy != "none" else None
        record_text: dict[str, str] = {}
        evidence = None
        if pack is not None:
            record_text = pack.record_text(redact)
            evidence = pack.render(redact)
        user = render_user(
            evidence=evidence,
            question=redactor.redact(question) if question is not None else None,
            # By field name, so strict mode replaces a bare host/user value (narrative filter).
            context={k: redactor.redact_value(v, k) for k, v in context.items()}
            if context
            else None,
            max_question_chars=self.max_question_chars,
        )
        schema = provider_schema(spec.output)
        messages: list[dict[str, str]] = [{"role": "user", "content": user}]
        outcome = RunOutcome(
            status="invalid",
            output={},
            parsed=None,
            problems=[],
            warnings=list(pack.warnings) if pack is not None else [],
            citations=None,
            response=None,
            model_requested=self.gateway.model_for(template.tier),
            prompt_text=user[:MAX_PROMPT_TEXT],
            prompt_sha256=_sha(template.system + "\n\x00\n" + user),
            input_sha256=(pack or EvidencePack()).input_sha256(
                {"question": question or "", "context": context or {}}
            ),
            prompt_version=template.prompt_version,
        )
        rejected: list[str] = []
        for attempt in (1, 2):
            req = LLMRequest(
                feature=spec.feature,
                tier=template.tier,
                system=template.system,
                messages=tuple(messages),
                schema=schema,
                max_tokens=self.max_tokens,
            )
            try:
                response, stats = self.gateway.complete(req, user_key=user_key, case_key=case_key)
            except AppError as exc:
                if attempt == 1:
                    raise
                # The corrective retry was refused (rate limit, size, provider): finish with the
                # first reply, whose tokens and provider call must still be recorded.
                outcome.problems = [*outcome.problems, f"corrective retry not sent: {exc.code}"]
                break
            outcome.attempts = attempt
            outcome.response = response
            outcome.latency_ms += stats.latency_ms
            outcome.input_tokens += response.input_tokens or 0
            outcome.output_tokens += response.output_tokens or 0
            outcome.output_sha256 = _sha(response.text)
            if response.stop_reason == "refusal":
                outcome.status = "refused"
                outcome.problems = ["the model declined to answer"]
                break
            problems = self._validate(spec, response, record_text, outcome)
            if not problems:
                outcome.status = "valid"
                outcome.problems = []
                break
            outcome.problems = problems
            rejected = problems
            if attempt == 2:
                break
            messages += [
                {"role": "assistant", "content": response.text[:MAX_ECHO] or "(empty)"},
                {
                    "role": "user",
                    "content": "Your previous reply was rejected by the validator: "
                    + "; ".join(problems)
                    + ". Reply again with one JSON object that follows the required schema and "
                    "cites only record ids that appear in the evidence block.",
                },
            ]
        outcome.redactions = redactor.summary()
        if outcome.status == "valid" and outcome.parsed is not None:
            outcome.output = redactor.restore(outcome.parsed.model_dump(mode="json"))
        else:
            raw = outcome.response.text if outcome.response else ""
            outcome.output = {"rejected_reply": redactor.restore(raw[:MAX_ECHO])}
        if outcome.citations is not None and outcome.citations.unsupported:
            outcome.warnings.append(
                {"type": "unsupported_claim", "items": outcome.citations.unsupported[:20]}
            )
        if outcome.attempts > 1 and outcome.status == "valid":
            outcome.warnings.append({"type": "retried", "problems": rejected[:5]})
        return outcome

    @staticmethod
    def _validate(
        spec: FeatureSpec,
        response: LLMResponse,
        record_text: dict[str, str],
        outcome: RunOutcome,
    ) -> list[str]:
        if response.stop_reason == "max_tokens":
            return ["the reply was cut off at the output token limit"]
        parsed, problems = parse_output(response.text, spec.output)
        if parsed is None:
            outcome.parsed = None
            outcome.citations = None
            return problems
        report = check_citations(
            parsed.model_dump(mode="json"),
            record_text,
            required=spec.required_cites,
            indicator_lists=spec.indicator_lists,
        )
        outcome.parsed = parsed
        outcome.citations = report
        problems = report.problems()
        if spec.extra_check is not None:
            problems += spec.extra_check(parsed)
        return problems

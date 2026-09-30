"""Output schemas per AI feature (guide 13.4). Validation is ours: every model forbids extra keys
and caps lengths and counts. ``provider_schema`` derives the JSON schema sent to providers for
constrained decoding, without the constraints structured outputs do not support (lengths, counts,
patterns, numeric bounds); those are enforced here after the call.
"""

from __future__ import annotations

import copy
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Cite = Annotated[str, StringConstraints(min_length=1, max_length=32)]
Cites = Annotated[list[Cite], Field(max_length=20)]
Technique = Annotated[str, StringConstraints(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]


T40 = Annotated[str, StringConstraints(max_length=40)]
T60 = Annotated[str, StringConstraints(max_length=60)]
T200 = Annotated[str, StringConstraints(max_length=200)]
T300 = Annotated[str, StringConstraints(max_length=300)]
T400 = Annotated[str, StringConstraints(max_length=400)]
T500 = Annotated[str, StringConstraints(max_length=500)]
T600 = Annotated[str, StringConstraints(max_length=600)]
T1000 = Annotated[str, StringConstraints(max_length=1000)]
T1500 = Annotated[str, StringConstraints(max_length=1500)]
T2000 = Annotated[str, StringConstraints(max_length=2000)]
T6000 = Annotated[str, StringConstraints(max_length=6000)]


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Fact(_Out):
    statement: T600
    cites: Cites


class NextStep(_Out):
    action: T300
    why: T400
    cites: Cites


class AttackCandidate(_Out):
    technique: Technique
    rationale: T400
    cites: Cites


class NlqOutput(_Out):
    """A1: question -> search-language query (validated with our own grammar)."""

    query: T2000 | None
    explanation: T1000
    assumptions: Annotated[list[T300], Field(max_length=10)]


class AlertExplanation(_Out):
    """A2: the guide 13.4 output format."""

    summary: T600
    assessment: Literal["likely_malicious", "suspicious", "likely_benign", "insufficient_evidence"]
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    key_facts: Annotated[list[Fact], Field(max_length=20)]
    next_steps: Annotated[list[NextStep], Field(max_length=10)]
    attack_candidates: Annotated[list[AttackCandidate], Field(max_length=10)]
    limitations: T600

    @model_validator(mode="after")
    def _facts_needed(self) -> AlertExplanation:
        if self.assessment != "insufficient_evidence" and not self.key_facts:
            raise ValueError("an assessment other than insufficient_evidence needs key_facts")
        return self


class TimelineEntry(_Out):
    ts: T40
    stage: T60
    statement: T600
    cites: Cites


class Narrative(_Out):
    """A3: chronological attack story with citations."""

    title: T200
    summary: T1500
    timeline: Annotated[list[TimelineEntry], Field(max_length=60)]
    gaps: Annotated[list[T300], Field(max_length=10)]
    limitations: T600


class ChatAnswer(_Out):
    """A5: answer from retrieved evidence only, or insufficient_evidence."""

    status: Literal["answered", "insufficient_evidence"]
    answer: T2000
    key_facts: Annotated[list[Fact], Field(max_length=20)]
    limitations: T600

    @model_validator(mode="after")
    def _facts_needed(self) -> ChatAnswer:
        if self.status == "answered" and not self.key_facts:
            raise ValueError("an answered question needs key_facts with citations")
        return self


class Behavior(_Out):
    description: T400
    cites: Cites


class Indicator(_Out):
    type: Literal["url", "domain", "ip", "email", "hash", "path", "registry", "other"]
    value: T500
    cites: Cites


class ScriptExplanation(_Out):
    """A7: static explanation of a script or command line (never executed)."""

    summary: T1000
    risk: Literal["benign", "suspicious", "malicious", "unknown"]
    behaviors: Annotated[list[Behavior], Field(max_length=20)]
    indicators: Annotated[list[Indicator], Field(max_length=50)]
    attack_candidates: Annotated[list[AttackCandidate], Field(max_length=10)]
    limitations: T600


class ReportDraft(_Out):
    """A4: a report section draft (Markdown) whose statements cite the snapshot records."""

    text: T6000
    claims: Annotated[list[Fact], Field(max_length=30)]
    limitations: T600

    @model_validator(mode="after")
    def _claims_needed(self) -> ReportDraft:
        if self.text.strip() and not self.claims:
            raise ValueError("a draft needs claims with citations")
        return self


UNSUPPORTED_KEYS = frozenset(
    {
        "maxLength",
        "minLength",
        "maximum",
        "minimum",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "multipleOf",
        "maxItems",
        "minItems",
        "uniqueItems",
        "pattern",
        "title",
        "description",
    }
)


def _strip(node: Any, *, names: bool = False) -> Any:
    """Remove unsupported keywords; ``names`` = this dict maps property/def names (kept as-is)."""
    if isinstance(node, dict):
        if names:
            return {k: _strip(v) for k, v in node.items()}
        out = {
            k: _strip(v, names=k in ("properties", "$defs"))
            for k, v in node.items()
            if k not in UNSUPPORTED_KEYS
        }
        if out.get("type") == "object":
            out["additionalProperties"] = False
            out.setdefault("required", sorted(out.get("properties", {})))
        return out
    if isinstance(node, list):
        return [_strip(v) for v in node]
    return node


def provider_schema(model: type[BaseModel]) -> dict[str, Any]:
    """JSON schema for constrained decoding (all objects closed, unsupported keywords removed)."""
    schema = copy.deepcopy(model.model_json_schema())
    return dict(_strip(schema))

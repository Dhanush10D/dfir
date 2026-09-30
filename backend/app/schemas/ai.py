"""AI API schemas (Phase 7). Model output is returned as validated JSON (``output``); every
response carries the provenance an analyst needs to judge it (guide 13.12)."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FEATURES = Literal["nlq", "alert_explain", "narrative", "chat", "script_explain", "report_draft"]


class AiStatusOut(BaseModel):
    enabled: bool
    provider: str
    local_only: bool
    configured: bool
    models: dict[str, str]
    embedding_model: str
    redaction_policy: str
    prompt_versions: dict[str, str]


class NlqRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: uuid.UUID
    question: str = Field(min_length=1, max_length=2000)


class NarrativeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: datetime | None = None
    end: datetime | None = None
    host: str | None = Field(default=None, max_length=255)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=2000)


class ScriptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: uuid.UUID
    text: str | None = Field(default=None, max_length=100_000)
    event_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _one_source(self) -> ScriptRequest:
        if (self.text is None) == (self.event_id is None):
            raise ValueError("give exactly one of 'text' or 'event_id'")
        return self


class ReportDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    section: str = Field(min_length=1, max_length=64, pattern=r"^[a-z_]+$")


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["accept", "reject"]
    note: str | None = Field(default=None, max_length=2000)
    acknowledge_warnings: bool = False


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: Literal[-1, 0, 1]


class CaseAiSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ai_enabled: bool


class CitationOut(BaseModel):
    short_id: str
    kind: str
    id: str | None
    ts: str | None
    summary: str


class InteractionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID | None
    user_id: uuid.UUID | None
    feature: str
    status: str
    provider: str
    model: str
    model_served: str | None
    prompt_version: str
    prompt_sha256: str | None
    input_sha256: str | None
    output_sha256: str | None
    started_at: datetime | None
    created_at: datetime
    latency_ms: int | None
    input_tokens: int | None
    output_tokens: int | None
    cost_usd: Decimal | None
    citations_valid: bool | None
    warnings: list[dict[str, Any]]
    error: str | None
    accepted: bool | None
    reviewed_by: uuid.UUID | None
    reviewed_at: datetime | None
    review_note: str | None
    feedback: int | None


class InteractionDetail(InteractionOut):
    output: dict[str, Any]
    citations: list[CitationOut]
    input_refs: dict[str, Any]
    prompt_text: str | None  # what was sent to the model (redacted)
    redaction_policy: str | None = None
    redaction_counts: dict[str, int] = Field(default_factory=dict)


class InteractionList(BaseModel):
    items: list[InteractionOut]
    total: int
    limit: int
    offset: int


class IndexOut(BaseModel):
    case_id: uuid.UUID
    built_at: datetime | None
    event_count: int
    chunk_count: int
    embedding_model: str | None
    truncated: bool
    stale: bool
    current_event_count: int
    rebuilt: bool = False


class FeatureOut(BaseModel):
    interaction: InteractionOut
    output: dict[str, Any]
    citations: dict[str, CitationOut]
    problems: list[str]
    extras: dict[str, Any] = Field(default_factory=dict)

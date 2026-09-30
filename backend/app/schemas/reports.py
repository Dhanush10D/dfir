"""Report API schemas (Phase 8)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ReportKind = Literal["technical", "executive", "custody", "ioc"]
DownloadFormat = Literal["html", "pdf", "json", "stix", "csv", "timeline", "custody", "seal"]


class ReportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: ReportKind
    title: str | None = Field(default=None, max_length=300)


class RefIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["event", "alert", "evidence"]
    id: uuid.UUID


class FindingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = Field(default=None, max_length=64)
    title: str = Field(min_length=1, max_length=300)
    body: str = Field(default="", max_length=20_000)
    confidence: Literal["low", "medium", "high"] = "medium"
    attack: list[str] = Field(default_factory=list, max_length=20)
    refs: list[RefIn] = Field(default_factory=list, max_length=50)


class ReportUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=0)
    title: str | None = Field(default=None, max_length=300)
    sections: dict[str, str] | None = Field(default=None, max_length=20)
    findings: list[FindingIn] | None = Field(default=None, max_length=200)


class RevisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=0)


class ReturnRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=2000)


class ApplyAiRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interaction_id: uuid.UUID
    expected_revision: int = Field(ge=0)


class SectionDefOut(BaseModel):
    name: str
    title: str
    required: bool
    ai_draft: bool


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    case_id: uuid.UUID
    family_id: uuid.UUID
    supersedes_id: uuid.UUID | None
    version: int
    kind: str
    title: str
    status: str
    revision: int
    context_sha256: str
    created_by: uuid.UUID | None
    created_at: datetime
    updated_by: uuid.UUID | None
    updated_at: datetime
    submitted_by: uuid.UUID | None
    submitted_at: datetime | None
    approved_by: uuid.UUID | None
    approved_at: datetime | None
    signed_by: uuid.UUID | None
    signed_at: datetime | None
    key_id: str | None
    sha256: str | None


class ReportDetail(ReportOut):
    sections: dict[str, Any]
    findings: list[dict[str, Any]]
    qa: dict[str, Any] | None
    signature: str | None
    manifest: dict[str, Any] | None
    section_defs: list[SectionDefOut]
    formats: list[str]
    counts: dict[str, Any]
    truncated: dict[str, Any]
    context: dict[str, Any] | None = None


class ReportList(BaseModel):
    items: list[ReportOut]


class VerifyOut(BaseModel):
    ok: bool
    report_id: str
    version: int
    manifest_sha256: str | None
    key_id: str | None
    signature_ok: bool
    artifacts: list[dict[str, Any]]
    problems: list[dict[str, Any]]
    checked_at: str | None

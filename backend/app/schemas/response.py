"""Playbook, run, approval and enrichment API schemas (Phase 9)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.response.schema import MAX_PLAYBOOK_BYTES, PLAYBOOK_ID_PATTERN

StepOp = Literal["complete", "skip", "request", "execute"]
RequestStatus = Literal["pending", "approved", "rejected", "expired", "finished"]


class PlaybookOut(BaseModel):
    id: str
    title: str
    description: str | None
    version: int
    enabled: bool
    origin: str
    sha256: str | None
    trigger: dict[str, Any]
    phases: list[Any]
    notify: dict[str, Any]
    updated_at: datetime


class PlaybookList(BaseModel):
    items: list[PlaybookOut]


class PlaybookImport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    yaml: str = Field(min_length=1, max_length=MAX_PLAYBOOK_BYTES)


class ActionInfo(BaseModel):
    name: str
    title: str
    impact: bool
    executor: str
    effect: str
    params: dict[str, dict[str, Any]]


class ActionList(BaseModel):
    items: list[ActionInfo]


class RunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    playbook_id: str = Field(pattern=PLAYBOOK_ID_PATTERN, max_length=64)
    alert_id: uuid.UUID | None = None  # the alert that triggered the response
    dry_run: bool = False  # true: return the plan, write nothing


class ActionRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    case_id: uuid.UUID
    run_id: uuid.UUID
    step_id: uuid.UUID
    alert_id: uuid.UUID | None
    action: str
    params: dict[str, Any]
    params_sha256: str
    status: str
    requested_by: uuid.UUID
    requested_at: datetime
    expires_at: datetime
    decided_by: uuid.UUID | None
    decided_at: datetime | None
    decision_reason: str | None
    executed_by: uuid.UUID | None
    executed_at: datetime | None
    outcome: str | None
    result: dict[str, Any] | None


class ActionRequestList(BaseModel):
    items: list[ActionRequestOut]


class StepOut(BaseModel):
    id: uuid.UUID
    position: int
    phase: str
    step_key: str
    text: str
    kind: str
    action: str | None
    action_title: str | None
    executor: str | None  # "none": the platform cannot execute this action in this profile
    params: dict[str, Any]
    requires_approval: bool
    status: str
    outcome: str | None
    result: dict[str, Any] | None
    notes: str | None
    completed_by: uuid.UUID | None
    completed_at: datetime | None
    updated_by: uuid.UUID | None
    updated_at: datetime
    alert_id: uuid.UUID | None  # the triggering alert of the run
    request: ActionRequestOut | None  # the newest approval request of this step


class RunOut(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    playbook_id: str
    playbook_version: int
    playbook_sha256: str | None
    title: str
    status: str
    alert_id: uuid.UUID | None
    started_by: uuid.UUID | None
    started_at: datetime
    finished_at: datetime | None


class RunDetail(RunOut):
    steps: list[StepOut]


class RunList(BaseModel):
    items: list[RunOut]


class StepPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    op: StepOp
    notes: str | None = Field(default=None, max_length=4000)
    params: dict[str, str | int] | None = Field(default=None, max_length=8)
    dry_run: bool = False  # true: return what the operation would do, change nothing


class CancelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=2000)


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(default=None, max_length=2000)


class RejectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=2000)


class EnrichRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ioc_ids: list[uuid.UUID] | None = Field(default=None, max_length=200)
    providers: list[Literal["virustotal", "misp"]] | None = Field(default=None, max_length=2)
    refresh: bool = False


class EnrichmentEntry(BaseModel):
    ioc_id: uuid.UUID
    provider: str
    status: str  # fetched | cached | stale | skipped_tlp | skipped_deadline | error
    verdict: str | None = None
    score: float | None = None
    summary: dict[str, Any] | None = None
    fetched_at: datetime | None = None
    expires_at: datetime | None = None
    tlp: str | None = None
    error: str | None = None


class EnrichmentResult(BaseModel):
    results: list[EnrichmentEntry]
    counts: dict[str, int]
    truncated: bool


class EnrichmentList(BaseModel):
    items: list[EnrichmentEntry]


class SightingResult(BaseModel):
    ioc_id: uuid.UUID
    provider: str
    exported: bool

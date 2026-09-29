"""Detection API schemas: detection runs, alerts, rules, IOCs (guide 15.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import AlertStatus, Severity
from app.schemas.events import EventOut
from app.schemas.jobs import JobOut

RULE_ID_PATTERN = r"^[A-Z][A-Z0-9]{1,15}(?:-[A-Z0-9]{1,16}){1,4}$"


class DetectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[str] | None = Field(
        default=None, max_length=200, description="Rule ids to run (default: all enabled rules)."
    )


class DetectOut(BaseModel):
    job: JobOut
    created: bool = Field(description="False when the request joined an already queued run.")


# ---------------------------------------------------------------------------------- alerts


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    rule_id: str | None
    rule_version: int | None
    title: str
    severity: Severity
    confidence: float
    risk_score: float
    status: AlertStatus
    status_reason: str | None
    host: str | None
    user: str | None
    attack_tags: list[str]
    dedup_key: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    assignee_id: uuid.UUID | None
    stale: bool
    last_detected_at: datetime | None
    last_job_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class AlertHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    action: str
    user_id: uuid.UUID | None
    job_id: uuid.UUID | None
    from_status: AlertStatus | None
    to_status: AlertStatus | None
    from_assignee: uuid.UUID | None
    to_assignee: uuid.UUID | None
    reason: str | None


class AlertDetail(AlertOut):
    details: dict[str, Any]
    history: list[AlertHistoryOut] = Field(default_factory=list)


class AlertList(BaseModel):
    items: list[AlertOut]
    total: int
    limit: int
    offset: int


class AlertUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AlertStatus | None = None
    assignee_id: uuid.UUID | None = Field(
        default=None, description="User to assign; send null to unassign."
    )
    reason: str | None = Field(default=None, max_length=2000)
    expected_status: AlertStatus | None = Field(
        default=None, description="Optimistic check: 409 if the alert's status differs."
    )


class AlertEventOut(BaseModel):
    event_id: uuid.UUID
    event_ts: datetime
    missing: bool = Field(description="The event no longer exists (e.g. mid-reprocess).")
    event: EventOut | None


class AlertEventList(BaseModel):
    items: list[AlertEventOut]
    total: int


class AttackRow(BaseModel):
    technique: str
    tactics: list[str]
    alerts: int
    max_severity: Severity


class RiskOut(BaseModel):
    case_risk: float
    tactics: list[str]
    hosts: list[dict[str, Any]]


# ---------------------------------------------------------------------------------- rules


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: str | None
    level: Severity
    status: str
    kind: str
    confidence: float
    attack: list[str]
    enabled: bool
    version: int
    origin: str
    sha256: str | None
    updated_at: datetime


class RuleVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    version: int
    sha256: str
    created_by: uuid.UUID | None
    created_at: datetime


class RuleDetail(RuleOut):
    raw_yaml: str
    logsource: dict[str, Any]
    versions: list[RuleVersionOut] = Field(default_factory=list)


class RuleList(BaseModel):
    items: list[RuleOut]


class RuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    yaml: str = Field(min_length=1, max_length=64 * 1024)
    enabled: bool = True


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    yaml: str | None = Field(default=None, min_length=1, max_length=64 * 1024)
    expected_version: int | None = Field(default=None, ge=1)


class SigmaImport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    yaml: str = Field(min_length=1, max_length=128 * 1024)
    rule_id: str | None = Field(default=None, pattern=RULE_ID_PATTERN, max_length=64)
    enabled: bool = True


class SigmaImportOut(BaseModel):
    rule: RuleDetail
    notes: list[str]


class SampleEvent(BaseModel):
    """A sample event for ``POST /rules/test`` (Appendix A fields; ``raw`` is optional)."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    ts: datetime
    host: str | None = Field(default=None, max_length=1024)
    user: str | None = Field(default=None, max_length=1024)
    event_code: str | None = Field(default=None, max_length=256)
    event_category: str | None = Field(default=None, max_length=256)
    action: str | None = Field(default=None, max_length=256)
    outcome: str | None = Field(default=None, max_length=256)
    process_name: str | None = Field(default=None, max_length=1024)
    pid: int | None = None
    ppid: int | None = None
    cmdline: str | None = Field(default=None, max_length=32 * 1024)
    file_path: str | None = Field(default=None, max_length=4096)
    file_hash: str | None = Field(default=None, max_length=256)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = Field(default=None, max_length=64)
    registry_key: str | None = Field(default=None, max_length=4096)
    message: str | None = Field(default=None, max_length=32 * 1024)
    source_type: str = Field(default="evtx", max_length=64)
    source_file: str | None = Field(default=None, max_length=1024)
    source_record_id: str | None = Field(default=None, max_length=64)
    recno: int | None = Field(default=None, ge=0)
    raw: dict[str, Any] | None = None

    @field_validator("ts")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("ts needs a timezone")
        return value


class RuleTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    yaml: str = Field(min_length=1, max_length=64 * 1024)
    events: list[SampleEvent] = Field(max_length=500)


class RuleTestOut(BaseModel):
    rule_id: str
    kind: str
    matches: int
    alerts: list[dict[str, Any]]
    warnings: dict[str, int]


class CoverageRow(BaseModel):
    technique: str
    tactics: list[str]
    rules: list[str]


# ---------------------------------------------------------------------------------- IOCs

IocType = Literal["ip", "domain", "url", "sha256", "sha1", "md5", "email", "filename"]
Tlp = Literal["clear", "white", "green", "amber", "amber+strict", "red"]


class IocCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: IocType
    value: str = Field(min_length=1, max_length=2048)
    source: str | None = Field(default=None, max_length=256)
    confidence: float | None = Field(default=None, ge=0, le=1)
    tlp: Tlp | None = None
    expires_at: datetime | None = None


class IocOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID | None
    type: str
    value: str
    value_original: str | None
    source: str | None
    confidence: float | None
    tlp: str | None
    expires_at: datetime | None
    active: bool
    created_by: uuid.UUID | None
    created_at: datetime


class IocList(BaseModel):
    items: list[IocOut]
    total: int


class IocImport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: Literal["csv", "json", "stix"]
    content: str = Field(min_length=1, max_length=2 * 1024 * 1024)
    tlp: Tlp | None = Field(default=None, description="TLP for items that carry none.")


class IocImportOut(BaseModel):
    created: int
    updated: int
    rejected: list[dict[str, Any]]
    rejected_count: int

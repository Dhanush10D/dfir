"""Integration API schemas and per-type configuration models (Phase 9).

Secrets are write-only: request bodies carry them, responses never do (``has_secret`` and a keyed
fingerprint only). ``config`` is non-secret configuration and is validated per type here.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.integrations.enrichment import MISP_MAX_TLP_CHOICES, VIRUSTOTAL_URL

IntegrationType = Literal[
    "webhook_out", "webhook_in", "slack", "teams", "email", "virustotal", "misp"
]
EventName = Literal[
    "alert.created",
    "case.status_changed",
    "report.signed",
    "evidence.verification_failed",
    "playbook.run_started",
    "playbook.approval_requested",
    "playbook.notice",
]
SeverityName = Literal["info", "low", "medium", "high", "critical"]
Url = Annotated[str, Field(min_length=8, max_length=2048)]
Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")]


class _Config(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _ChannelConfig(_Config):
    events: list[EventName] = Field(default_factory=list, max_length=7)
    min_severity: SeverityName | None = None  # applies to events that carry a severity
    include_details: bool = False  # also send evidence-derived text (alert title, host)
    case_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)  # empty = every case


class WebhookOutConfig(_ChannelConfig):
    url: Url


class SlackConfig(_ChannelConfig):
    pass


class TeamsConfig(_ChannelConfig):
    pass


class EmailConfig(_ChannelConfig):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=587, ge=1, le=65535)
    security: Literal["starttls", "tls", "none"] = "starttls"
    username: str | None = Field(default=None, max_length=256)
    sender: str = Field(min_length=3, max_length=320)
    recipients: list[str] = Field(min_length=1, max_length=20)


class WebhookInConfig(_Config):
    # our field -> dotted path in the sender's JSON (see app/integrations/inbound.py)
    field_map: dict[str, str] = Field(default_factory=dict, max_length=10)


class VirusTotalConfig(_Config):
    base_url: Url = VIRUSTOTAL_URL


class MispConfig(_Config):
    url: Url
    max_tlp: Literal["clear", "green", "amber", "amber+strict"] = "green"


CONFIG_MODELS: dict[str, type[_Config]] = {
    "webhook_out": WebhookOutConfig,
    "webhook_in": WebhookInConfig,
    "slack": SlackConfig,
    "teams": TeamsConfig,
    "email": EmailConfig,
    "virustotal": VirusTotalConfig,
    "misp": MispConfig,
}
# Secret field per type: (name, required to enable, minimum length)
SECRET_FIELDS: dict[str, tuple[tuple[str, bool, int], ...]] = {
    "webhook_out": (("signing_secret", True, 32),),
    "webhook_in": (("signing_secret", True, 32),),
    "slack": (("webhook_url", True, 8),),
    "teams": (("webhook_url", True, 8),),
    "email": (("password", False, 1),),
    "virustotal": (("api_key", True, 8),),
    "misp": (("api_key", True, 8),),
}
if set(MISP_MAX_TLP_CHOICES) != {"clear", "green", "amber", "amber+strict"}:  # pragma: no cover
    raise RuntimeError("MispConfig.max_tlp is out of sync with the provider")


class IntegrationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: IntegrationType
    name: Name
    config: dict[str, Any] = Field(default_factory=dict)
    # Write-only. Never returned, logged or audited.
    secret: dict[str, SecretStr] | None = Field(default=None, max_length=4)
    enabled: bool = False
    case_id: uuid.UUID | None = None  # webhook_in: the case its deliveries go to


class IntegrationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Name | None = None
    config: dict[str, Any] | None = None
    secret: dict[str, SecretStr] | None = Field(default=None, max_length=4)
    enabled: bool | None = None
    case_id: uuid.UUID | None = None


class IntegrationOut(BaseModel):
    id: uuid.UUID
    type: str
    name: str
    enabled: bool
    config: dict[str, Any]
    case_id: uuid.UUID | None
    has_secret: bool
    secret_fingerprint: str | None
    secret_key_id: str | None
    last_status: str | None
    last_status_at: datetime | None
    created_at: datetime
    updated_at: datetime


class IntegrationList(BaseModel):
    items: list[IntegrationOut]
    secrets_available: bool  # false = no key-encryption key configured; secrets cannot be saved


class DeliveryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    event_id: uuid.UUID
    event_type: str
    kind: str
    status: str
    attempts: int
    max_attempts: int
    next_attempt_at: datetime | None
    last_error: str | None
    response_status: int | None
    created_at: datetime
    delivered_at: datetime | None


class InboundDeliveryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    received_at: datetime
    source_ip: str | None
    body_sha256: str
    items: int
    created: int
    updated: int
    errors: int
    error_reasons: dict[str, Any]

    @field_validator("source_ip", mode="before")
    @classmethod
    def _ip_text(cls, value: object) -> object:
        return str(value) if value is not None else None


class DeliveryLog(BaseModel):
    outbound: list[DeliveryOut]
    inbound: list[InboundDeliveryOut]


class QueuedTest(BaseModel):
    event_id: uuid.UUID
    queued: bool


class NotificationRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event: EventName
    min_severity: SeverityName | None = None
    recipients: list[Literal["admins", "case_lead", "case_members", "case_approvers"]] = Field(
        min_length=1, max_length=4
    )
    enabled: bool = True


class NotificationRules(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: list[NotificationRule] = Field(max_length=50)


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    kind: str
    payload: dict[str, Any]
    case_id: uuid.UUID | None
    read_at: datetime | None
    created_at: datetime


class NotificationList(BaseModel):
    items: list[NotificationOut]
    unread: int


class IngestResult(BaseModel):
    accepted: bool
    duplicate: bool
    items: int
    created: int
    updated: int
    errors: int
    error_reasons: dict[str, int]

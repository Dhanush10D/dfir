"""Case and membership schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models.enums import CaseStatus, Severity, UserRole


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=20000)
    severity: Severity = Severity.medium
    classification: str | None = Field(default=None, max_length=64)
    case_number: str | None = Field(
        default=None, max_length=32, description="Default: IR-YYYY-NNNN"
    )


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=20000)
    severity: Severity | None = None
    classification: str | None = Field(default=None, max_length=64)
    status: CaseStatus | None = None
    lead_id: uuid.UUID | None = None


class CaseClose(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_number: str
    title: str
    description: str | None
    status: CaseStatus
    severity: Severity
    classification: str | None
    lead_id: uuid.UUID | None
    created_by: uuid.UUID | None
    opened_at: datetime
    closed_at: datetime | None
    ai_enabled: bool = True  # Phase 7: AI features switched on for this case


class CaseDetail(CaseOut):
    my_case_role: UserRole | None = None
    my_permissions: list[str] = Field(default_factory=list)


class CaseList(BaseModel):
    items: list[CaseOut]
    next_cursor: str | None = None
    total: int


class MemberSet(BaseModel):
    user_id: uuid.UUID
    role: UserRole = UserRole.analyst


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    display_name: str
    global_role: UserRole
    case_role: UserRole

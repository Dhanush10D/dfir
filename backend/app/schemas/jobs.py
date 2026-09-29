"""Processing job schemas (guide 15.2 "Jobs", 10.1 run manifest)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import JobStatus


class ProcessParams(BaseModel):
    """Parser parameters. Unknown keys are rejected; each parser accepts only its own."""

    model_config = ConfigDict(extra="forbid")

    timezone: str | None = Field(
        default=None,
        max_length=64,
        description="IANA zone for timestamps without an offset (syslog). Default UTC.",
    )
    year: int | None = Field(
        default=None,
        ge=1970,
        le=2100,
        description="Year of the FIRST syslog line (default: inferred from acquisition time).",
    )
    os: str | None = Field(
        default=None, max_length=16, description="volatility: 'windows' (default) or 'linux'."
    )
    plugins: list[Annotated[str, Field(max_length=32)]] | None = Field(
        default=None,
        max_length=16,
        description="volatility: plugin subset from the per-OS allowlist (docs/parsers.md).",
    )


class ProcessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parsers: list[str] | Literal["auto"] = Field(
        default="auto", description="Parser names, or 'auto' to detect from the content."
    )
    params: ProcessParams = Field(default_factory=ProcessParams)


class ReprocessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    params: ProcessParams | None = Field(
        default=None, description="New parameters (default: the job's parameters)."
    )


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    evidence_id: uuid.UUID | None
    kind: str
    parser: str | None
    params: dict[str, Any]
    status: JobStatus
    progress: float
    attempts: int
    error: str | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    heartbeat_at: datetime | None
    created_by: uuid.UUID | None
    superseded_by: uuid.UUID | None
    counts: dict[str, int] | None = None


class JobDetail(JobOut):
    run_manifest: dict[str, Any] | None


class JobList(BaseModel):
    items: list[JobOut]


class ProcessOut(BaseModel):
    jobs: list[JobOut]
    created: list[uuid.UUID] = Field(description="Jobs created by this request (others existed).")


class ParserOut(BaseModel):
    name: str
    version: str
    description: str
    source_types: list[str]
    params: list[str]

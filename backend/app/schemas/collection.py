"""Triage bundle ingest schemas (Phase 5, guide 9.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.schemas.jobs import JobOut


class BundleMemberOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    member_path: str
    member_index: int | None
    size_bytes: int | None
    sha256_manifest: str | None
    sha256_actual: str | None
    status: str
    parser: str | None
    derived_evidence_id: uuid.UUID | None
    parse_job_id: uuid.UUID | None
    detail: dict[str, Any]


class DerivedEvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    label: str
    kind: str
    original_name: str
    sha256: str | None
    status: str
    created_at: datetime


class BundleSummaryOut(BaseModel):
    evidence_id: uuid.UUID
    job: JobOut | None
    outcome: str | None
    collector: dict[str, Any] | None
    collector_trust: dict[str, Any] | None
    host: dict[str, Any] | None
    manifest_sha256: str | None
    counts: dict[str, int]
    rejected: list[dict[str, Any]]
    members: list[BundleMemberOut]
    derived: list[DerivedEvidenceOut]

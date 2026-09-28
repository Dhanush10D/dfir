"""Evidence, custody and verification schemas (guide 15.2 "Evidence and custody", 15.4)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

HEX64 = r"^[0-9a-fA-F]{64}$"
HEX32 = r"^[0-9a-fA-F]{32}$"


class EvidenceCreate(BaseModel):
    label: str | None = Field(default=None, max_length=64, description="Default: EV-NNN")
    kind: str = Field(description="disk_image|memory|evtx|pcap|triage_bundle|log|file|cloud_export")
    original_name: str = Field(min_length=1, max_length=1024)
    size_bytes: int | None = Field(default=None, ge=0)
    mime_type: str | None = Field(default=None, max_length=255)
    source_host: str | None = Field(default=None, max_length=255)
    acquired_at: datetime | None = None
    acquired_by: str | None = Field(default=None, max_length=255)
    acquisition_tool: str | None = Field(default=None, max_length=255)
    acquisition_notes: str | None = Field(default=None, max_length=20000)
    expected_sha256: str | None = Field(default=None, pattern=HEX64)
    expected_md5: str | None = Field(default=None, pattern=HEX32)


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    label: str
    kind: str
    original_name: str
    size_bytes: int | None
    sha256: str | None
    md5: str | None
    expected_sha256: str | None
    expected_md5: str | None
    storage_uri: str
    storage_version_id: str | None
    retain_until: datetime | None
    mime_type: str | None
    source_host: str | None
    acquired_at: datetime | None
    acquired_by: str | None
    acquisition_tool: str | None
    acquisition_notes: str | None
    status: str
    uploaded_by: uuid.UUID | None
    created_at: datetime


class UploadSession(BaseModel):
    protocol: Literal["raw-put"] = "raw-put"
    method: Literal["PUT"] = "PUT"
    url: str
    content_type: str = "application/octet-stream"
    max_bytes: int
    finalize_url: str


class EvidenceCreated(BaseModel):
    evidence: EvidenceOut
    upload: UploadSession


class EvidenceList(BaseModel):
    items: list[EvidenceOut]
    next_cursor: str | None = None
    total: int


class FinalizeOut(BaseModel):
    ok: bool
    evidence: EvidenceOut
    computed: dict[str, Any]
    mismatches: list[dict[str, Any]]
    retention_mode: str | None
    retain_until: datetime | None


class CustodyEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    seq: int
    ts: datetime
    actor_id: uuid.UUID | None
    actor_label: str
    action: str
    detail: dict[str, Any]
    prev_hash: str
    entry_hash: str
    signature: str
    key_id: str


class CustodyChainOut(BaseModel):
    evidence_id: uuid.UUID
    entries: list[CustodyEntryOut]


class ChainProblemOut(BaseModel):
    seq: int
    code: str
    message: str


class ChainReportOut(BaseModel):
    ok: bool
    entries: int
    head_seq: int | None
    head_hash: str | None
    first_broken_seq: int | None
    broken_seqs: list[int]
    problems: list[ChainProblemOut]


class VerifyOut(BaseModel):
    ok: bool
    status: Literal["verified", "integrity_failure"]
    evidence_id: uuid.UUID
    evidence_status: str
    verified_at: datetime
    object: dict[str, Any]
    chain: ChainReportOut
    custody_entry: CustodyEntryOut


class SigningKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key_id: str
    algorithm: str
    public_key: str
    purpose: str
    created_at: datetime
    retired_at: datetime | None

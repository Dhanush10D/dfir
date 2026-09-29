"""Timeline event schemas (Appendix A field dictionary)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    evidence_id: uuid.UUID | None
    job_id: uuid.UUID | None
    ts: datetime
    ts_original: str | None
    source_type: str
    source_file: str | None
    source_record_id: str | None
    host: str | None
    user: str | None
    event_code: str | None
    event_category: str | None
    action: str | None
    outcome: str | None
    process_name: str | None
    pid: int | None
    ppid: int | None
    cmdline: str | None
    file_path: str | None
    file_hash: str | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    registry_key: str | None
    message: str | None
    attack_tags: list[str]
    tags: list[str]
    parser_name: str | None
    parser_version: str | None
    ingested_at: datetime

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def _ip(cls, value: Any) -> str | None:  # inet comes back as ipaddress objects
        return None if value is None else str(value)


class EventDetail(EventOut):
    raw: dict[str, Any] | None


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: str | None
    limit: int

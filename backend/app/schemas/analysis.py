"""Phase 4 analysis schemas: search, histogram, facets, context, export, notes, bookmarks,
entities, graph, process tree, case summary (guide 15.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.events import EventOut
from app.search.language import MAX_QUERY

TargetType = Literal["case", "event", "alert", "evidence", "entity"]


class _Query(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    query: str | None = Field(default=None, max_length=MAX_QUERY, description="Search language")
    start: datetime | None = Field(default=None, alias="from", description="Inclusive, with zone")
    end: datetime | None = Field(default=None, alias="to", description="Inclusive, with zone")


class SearchRequest(_Query):
    order: Literal["asc", "desc"] = "asc"
    limit: int = Field(default=100, ge=1, le=500)
    cursor: str | None = Field(default=None, max_length=256)


class HistogramRequest(_Query):
    buckets: int = Field(default=60, ge=10, le=200)


class FacetsRequest(_Query):
    fields: list[str] = Field(min_length=1, max_length=8)
    size: int = Field(default=10, ge=1, le=50)


class ContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: uuid.UUID
    minutes: int = Field(default=5, ge=1, le=1440)
    limit: int = Field(default=200, ge=1, le=500)


class ExportRequest(_Query):
    format: Literal["csv", "json"] = "csv"
    limit: int | None = Field(default=None, ge=1)


class FieldOut(BaseModel):
    name: str
    type: str
    ops: list[str]


class HistogramBucket(BaseModel):
    ts: str
    count: int
    by: dict[str, int]


class HistogramOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    interval_seconds: int
    start: str | None = Field(alias="from")
    end: str | None = Field(alias="to")
    buckets: list[HistogramBucket]
    series: list[str]
    total: int


class FacetValue(BaseModel):
    value: str
    count: int


class FacetsOut(BaseModel):
    fields: dict[str, list[FacetValue]]


class ContextOut(BaseModel):
    anchor: EventOut
    items: list[EventOut]


# ---------------------------------------------------------------------------------- notes


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body_md: str = Field(min_length=1, max_length=20000)
    target_type: TargetType | None = None
    target_id: str | None = Field(default=None, max_length=64)
    tags: list[str] = Field(default_factory=list, max_length=16)


class NoteUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=1)
    body_md: str | None = Field(default=None, min_length=1, max_length=20000)
    tags: list[str] | None = Field(default=None, max_length=16)
    reason: str | None = Field(default=None, max_length=2000)


class NoteRetract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=1)
    reason: str | None = Field(default=None, max_length=2000)


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    author_id: uuid.UUID
    target_type: str | None
    target_id: str | None
    body_md: str
    tags: list[str]
    version: int
    created_at: datetime
    updated_at: datetime
    updated_by: uuid.UUID | None
    retracted_at: datetime | None
    retracted_by: uuid.UUID | None


class NoteVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    version: int
    action: str
    body_md: str
    tags: list[str]
    user_id: uuid.UUID
    reason: str | None
    created_at: datetime


class NoteDetail(NoteOut):
    versions: list[NoteVersionOut]


class NoteList(BaseModel):
    items: list[NoteOut]
    total: int


class BookmarkCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_type: TargetType
    target_id: str | None = Field(default=None, max_length=64)
    comment: str | None = Field(default=None, max_length=2000)


class BookmarkOut(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    user_id: uuid.UUID
    user_name: str | None
    target_type: str
    target_id: str
    comment: str | None
    created_at: datetime
    event: EventOut | None = None


# ---------------------------------------------------------------------------------- entities


class EntityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    type: str
    canonical: str
    attributes: dict[str, Any]
    first_seen: datetime | None
    last_seen: datetime | None
    event_count: int


class EntityList(BaseModel):
    items: list[EntityOut]
    total: int


class AliasOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alias_type: str
    alias: str
    confidence: float


class NeighbourOut(BaseModel):
    entity: EntityOut
    relation: str
    direction: Literal["in", "out"]
    weight: int
    first_seen: datetime | None
    last_seen: datetime | None


class EntityDetailOut(EntityOut):
    aliases: list[AliasOut]
    neighbours: list[NeighbourOut]
    alert_count: int
    pivot_query: str | None


class EdgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    src_entity: uuid.UUID
    dst_entity: uuid.UUID
    relation: str
    weight: int
    first_seen: datetime | None
    last_seen: datetime | None


class GraphOut(BaseModel):
    nodes: list[EntityOut]
    edges: list[EdgeOut]
    truncated: bool


class ProcessNodeOut(BaseModel):
    key: str
    pid: int | None
    ppid: int | None
    name: str | None
    kind: str
    ts: datetime | None
    image: str | None
    cmdline: str | None
    user: str | None
    event_id: str | None
    parent: str | None
    depth: int
    children: int
    flags: list[str]
    alerts: int


class ProcessTreeOut(BaseModel):
    host: str
    nodes: list[ProcessNodeOut]
    roots: list[str]
    truncated: bool
    cycles_broken: int
    depth_capped: int


class SummaryOut(BaseModel):
    case_id: uuid.UUID
    events: int
    evidence: int
    entities: int
    notes: int
    jobs_active: int
    first_event: datetime | None
    last_event: datetime | None
    alerts_by_status: dict[str, int]
    alerts_by_severity: dict[str, int]
    top_hosts: list[FacetValue]
    top_users: list[FacetValue]
    risk: dict[str, Any]

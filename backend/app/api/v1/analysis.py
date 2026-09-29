"""Entities, entity graph, process tree and case summary (guide 12.3-12.6, 15.2 "Entities and
graph", ``/cases/{id}/summary``). HTTP only; logic in ``services/entities.py`` and
``services/proctree.py``."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.dependencies import CurrentPrincipal, EntitiesSvc, ProcTrees, Summaries
from app.schemas.analysis import (
    AliasOut,
    EdgeOut,
    EntityDetailOut,
    EntityList,
    EntityOut,
    GraphOut,
    NeighbourOut,
    ProcessNodeOut,
    ProcessTreeOut,
    SummaryOut,
)

router = APIRouter(tags=["analysis"])
CsvList = Annotated[str | None, Query(max_length=200, description="Comma-separated")]


def _split(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()][:16]


@router.get("/cases/{case_id}/entities", response_model=EntityList)
def list_entities(
    case_id: uuid.UUID,
    principal: CurrentPrincipal,
    entities: EntitiesSvc,
    type: Annotated[str | None, Query(max_length=16)] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EntityList:
    rows, total = entities.list_entities(
        principal, case_id, type_=type, q=q, limit=limit, offset=offset
    )
    return EntityList(items=[EntityOut.model_validate(e) for e in rows], total=total)


@router.get("/entities/{entity_id}", response_model=EntityDetailOut)
def get_entity(
    entity_id: uuid.UUID, principal: CurrentPrincipal, entities: EntitiesSvc
) -> EntityDetailOut:
    detail = entities.get(principal, entity_id)
    base = EntityOut.model_validate(detail.entity)
    return EntityDetailOut(
        **base.model_dump(),
        aliases=[AliasOut.model_validate(a) for a in detail.aliases],
        neighbours=[
            NeighbourOut(
                entity=EntityOut.model_validate(n["entity"]),
                relation=n["relation"],
                direction=n["direction"],
                weight=n["weight"],
                first_seen=n["first_seen"],
                last_seen=n["last_seen"],
            )
            for n in detail.neighbours
        ],
        alert_count=detail.alert_count,
        pivot_query=detail.pivot_query,
    )


@router.get("/cases/{case_id}/graph", response_model=GraphOut)
def graph(
    case_id: uuid.UUID,
    principal: CurrentPrincipal,
    entities: EntitiesSvc,
    entity_id: uuid.UUID | None = None,
    depth: Annotated[int, Query(ge=1, le=2)] = 1,
    types: CsvList = None,
    relations: CsvList = None,
    max_nodes: Annotated[int, Query(ge=1, le=500)] = 150,
    max_edges: Annotated[int, Query(ge=1, le=2000)] = 1000,
) -> GraphOut:
    result = entities.graph(
        principal,
        case_id,
        entity_id=entity_id,
        depth=depth,
        types=_split(types),
        relations=_split(relations),
        max_nodes=max_nodes,
        max_edges=max_edges,
    )
    return GraphOut(
        nodes=[EntityOut.model_validate(n) for n in result.nodes],
        edges=[EdgeOut.model_validate(e) for e in result.edges],
        truncated=result.truncated,
    )


@router.get("/cases/{case_id}/process-tree", response_model=ProcessTreeOut)
def process_tree(
    case_id: uuid.UUID,
    principal: CurrentPrincipal,
    trees: ProcTrees,
    host: Annotated[str, Query(min_length=1, max_length=255)],
    start: Annotated[datetime | None, Query(alias="from")] = None,
    end: Annotated[datetime | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 2000,
    max_depth: Annotated[int, Query(ge=1, le=128)] = 64,
) -> ProcessTreeOut:
    tree, alerts = trees.tree(
        principal, case_id, host=host, start=start, end=end, limit=limit, max_depth=max_depth
    )
    return ProcessTreeOut(
        host=host,
        nodes=[
            ProcessNodeOut(
                key=n.key,
                pid=n.pid,
                ppid=n.ppid,
                name=n.name,
                kind=n.kind,
                ts=n.ts,
                image=n.image,
                cmdline=n.cmdline,
                user=n.user,
                event_id=n.event_id,
                parent=n.parent,
                depth=n.depth,
                children=len(n.children),
                flags=n.flags,
                alerts=alerts.get(n.event_id or "", 0),
            )
            for n in tree.nodes
        ],
        roots=tree.roots,
        truncated=tree.truncated,
        cycles_broken=tree.cycles_broken,
        depth_capped=tree.depth_capped,
    )


@router.get("/cases/{case_id}/summary", response_model=SummaryOut)
def summary(case_id: uuid.UUID, principal: CurrentPrincipal, summaries: Summaries) -> SummaryOut:
    return SummaryOut.model_validate(summaries.summary(principal, case_id))

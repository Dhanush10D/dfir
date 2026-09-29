"""Entities and the entity graph (guide 12.3, 12.4).

Writing: :func:`write_resolution` persists an :class:`~app.analysis.entities.Resolution` produced
during a detection run (idempotent upserts in sorted key order, so concurrent runs take row locks
in the same order). Reading (:class:`EntityService`): list/search, detail with aliases, neighbours,
alert count and a ready-made pivot query, and a capped graph (nodes <= 500, edges <= 2000,
neighbourhood depth <= 2). Everything is case scoped; a cross-case entity id is *not found*.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, literal, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.analysis.entities import Key, Resolution
from app.config import Settings
from app.core.exceptions import AppError, NotFoundError
from app.core.permissions import Permission, Principal
from app.db.models import Alert, Entity, EntityAlias, EntityLink
from app.db.models.entities import ENTITY_TYPES, RELATIONS
from app.search.compile import like_pattern
from app.search.language import quote_value
from app.services.authz import CaseAccess, load_case_access

MAX_NODES, MAX_EDGES, MAX_DEPTH = 500, 2000, 2
WRITE_BATCH = 500
MAX_LIST = 500
PIVOT_FIELD = {"host": "host", "user": "user", "ip": "ip", "hash": "file_hash"}


@dataclass(frozen=True)
class EntityDetail:
    entity: Entity
    aliases: list[EntityAlias]
    neighbours: list[dict[str, Any]]
    alert_count: int
    pivot_query: str | None


@dataclass(frozen=True)
class Graph:
    nodes: list[Entity]
    edges: list[EntityLink]
    truncated: bool


def _chunks(items: Sequence[Any], size: int) -> list[Sequence[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def write_resolution(
    session: Session, case_id: uuid.UUID, job_id: uuid.UUID | None, res: Resolution
) -> dict[str, int]:
    """Upsert entities, aliases and links (caller holds the job fence and commits)."""
    keys = sorted(res.entities)
    ids: dict[Key, uuid.UUID] = {}
    for chunk in _chunks(keys, WRITE_BATCH):
        values = []
        for key in chunk:
            ent = res.entities[key]
            values.append(
                {
                    "case_id": case_id,
                    "type": ent.type,
                    "canonical": ent.canonical,
                    "attributes": ent.attributes,
                    "first_seen": ent.first_seen,
                    "last_seen": ent.last_seen,
                    "event_count": ent.event_count,
                    "last_job_id": job_id,
                }
            )
        ins = pg_insert(Entity).values(values)
        upsert = ins.on_conflict_do_update(
            index_elements=["case_id", "type", "canonical"],
            set_={
                "attributes": Entity.attributes.op("||")(ins.excluded.attributes),
                "first_seen": ins.excluded.first_seen,
                "last_seen": ins.excluded.last_seen,
                "event_count": ins.excluded.event_count,
                "last_job_id": ins.excluded.last_job_id,
                "updated_at": func.now(),
            },
        ).returning(Entity.id, Entity.type, Entity.canonical)
        for row in session.execute(upsert):
            ids[(row.type, row.canonical)] = row.id
    alias_rows = [
        {"entity_id": ids[key], "alias_type": at, "alias": alias}
        for key in keys
        for at, alias in sorted(res.entities[key].aliases)
    ]
    for chunk in _chunks(alias_rows, WRITE_BATCH):
        session.execute(pg_insert(EntityAlias).values(list(chunk)).on_conflict_do_nothing())
    link_rows = [
        {
            "case_id": case_id,
            "src_entity": ids[link.src],
            "dst_entity": ids[link.dst],
            "relation": link.relation,
            "event_id": link.event_id,
            "ts": link.first_seen,
            "first_seen": link.first_seen,
            "last_seen": link.last_seen,
            "weight": min(link.weight, 2**31 - 1),
        }
        for link in res.links
        if link.src in ids and link.dst in ids
    ]
    for chunk in _chunks(link_rows, WRITE_BATCH):
        stmt = pg_insert(EntityLink).values(list(chunk))
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=["case_id", "src_entity", "dst_entity", "relation"],
                set_={
                    "weight": stmt.excluded.weight,
                    "first_seen": stmt.excluded.first_seen,
                    "last_seen": stmt.excluded.last_seen,
                    "ts": stmt.excluded.ts,
                    "event_id": stmt.excluded.event_id,
                },
            )
        )
    return {"entities": len(ids), "aliases": len(alias_rows), "links": len(link_rows)}


class EntityService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def _access(self, principal: Principal, case_id: uuid.UUID) -> CaseAccess:
        access = load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )
        access.require(Permission.CASE_READ)
        return access

    def list_entities(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        *,
        type_: str | None = None,
        q: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Entity], int]:
        self._access(principal, case_id)
        if not 1 <= limit <= MAX_LIST or offset < 0:
            raise AppError("invalid_filter", f"'limit' must be 1-{MAX_LIST}.", 422)
        if type_ is not None and type_ not in ENTITY_TYPES:
            raise AppError("invalid_filter", "Unknown entity type.", 422, {"allowed": ENTITY_TYPES})
        conds = [Entity.case_id == case_id]
        if type_ is not None:
            conds.append(Entity.type == type_)
        if q:
            pattern = "%" + like_pattern(q.lower()) + "%"
            alias_hit = (
                select(literal(1))
                .select_from(EntityAlias)
                .where(
                    EntityAlias.entity_id == Entity.id,
                    EntityAlias.alias.ilike(pattern, escape="\\"),
                )
                .exists()
            )
            conds.append(or_(Entity.canonical.ilike(pattern, escape="\\"), alias_hit))
        total = self.session.execute(
            select(func.count()).select_from(Entity).where(*conds)
        ).scalar_one()
        rows = list(
            self.session.execute(
                select(Entity)
                .where(*conds)
                .order_by(Entity.event_count.desc(), Entity.type, Entity.canonical)
                .limit(limit)
                .offset(offset)
            ).scalars()
        )
        self.session.commit()
        return rows, int(total)

    def _load(self, principal: Principal, entity_id: uuid.UUID) -> Entity:
        entity = self.session.get(Entity, entity_id)
        if entity is None:
            raise NotFoundError("Entity not found.")
        try:
            self._access(principal, entity.case_id)
        except NotFoundError as exc:
            raise NotFoundError("Entity not found.") from exc
        return entity

    def get(self, principal: Principal, entity_id: uuid.UUID) -> EntityDetail:
        entity = self._load(principal, entity_id)
        aliases = list(
            self.session.execute(
                select(EntityAlias)
                .where(EntityAlias.entity_id == entity_id)
                .order_by(EntityAlias.alias_type, EntityAlias.alias)
            ).scalars()
        )
        links = list(
            self.session.execute(
                select(EntityLink)
                .where(
                    EntityLink.case_id == entity.case_id,
                    or_(EntityLink.src_entity == entity_id, EntityLink.dst_entity == entity_id),
                )
                .order_by(EntityLink.weight.desc(), EntityLink.id)
                .limit(100)
            ).scalars()
        )
        other_ids = {
            (l.dst_entity if l.src_entity == entity_id else l.src_entity)
            for l in links  # noqa: E741
        }
        others = (
            {
                e.id: e
                for e in self.session.execute(
                    select(Entity).where(Entity.id.in_(other_ids))
                ).scalars()
            }
            if other_ids
            else {}
        )
        neighbours = []
        for link in links:
            outgoing = link.src_entity == entity_id
            other = others.get(link.dst_entity if outgoing else link.src_entity)
            if other is None:
                continue
            neighbours.append(
                {
                    "entity": other,
                    "relation": link.relation,
                    "direction": "out" if outgoing else "in",
                    "weight": link.weight,
                    "first_seen": link.first_seen,
                    "last_seen": link.last_seen,
                }
            )
        observed = sorted({a.alias for a in aliases if a.alias_type in ("hostname", "name")})
        alert_count = 0
        if entity.type in ("host", "user") and observed:
            column = Alert.host if entity.type == "host" else Alert.user
            alert_count = int(
                self.session.execute(
                    select(func.count())
                    .select_from(Alert)
                    .where(Alert.case_id == entity.case_id, func.lower(column).in_(observed))
                ).scalar_one()
            )
        self.session.commit()
        return EntityDetail(
            entity, aliases, neighbours, alert_count, self.pivot_query(entity, aliases)
        )

    @staticmethod
    def pivot_query(entity: Entity, aliases: Sequence[EntityAlias]) -> str | None:
        field = PIVOT_FIELD.get(entity.type)
        if entity.type == "process":
            name = entity.canonical.rsplit("/", 1)[-1]
            return f"process_name:{quote_value(name)}"
        if field is None:
            return None
        values: list[str]
        if entity.type in ("host", "user"):
            values = sorted({a.alias for a in aliases if a.alias_type in ("hostname", "name")})[:20]
            values = values or [entity.canonical]
        else:
            values = [entity.canonical]
        return " OR ".join(f"{field}:{quote_value(v)}" for v in values)

    def graph(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        *,
        entity_id: uuid.UUID | None = None,
        depth: int = 1,
        types: list[str] | None = None,
        relations: list[str] | None = None,
        max_nodes: int = 150,
        max_edges: int = 1000,
    ) -> Graph:
        self._access(principal, case_id)
        if not 1 <= depth <= MAX_DEPTH:
            raise AppError("invalid_filter", f"'depth' must be 1-{MAX_DEPTH}.", 422)
        if not 1 <= max_nodes <= MAX_NODES or not 1 <= max_edges <= MAX_EDGES:
            raise AppError(
                "invalid_filter", f"max_nodes 1-{MAX_NODES}, max_edges 1-{MAX_EDGES}.", 422
            )
        bad = [t for t in types or [] if t not in ENTITY_TYPES] + [
            r for r in relations or [] if r not in RELATIONS
        ]
        if bad:
            raise AppError(
                "invalid_filter", "Unknown entity types or relations.", 422, {"bad": bad}
            )
        link_conds: list[Any] = [EntityLink.case_id == case_id]
        if relations:
            link_conds.append(EntityLink.relation.in_(relations))
        allowed_types = set(types or ENTITY_TYPES)
        truncated = False
        nodes: dict[uuid.UUID, Entity] = {}
        if entity_id is not None:
            root = self.session.execute(
                select(Entity).where(Entity.id == entity_id, Entity.case_id == case_id)
            ).scalar_one_or_none()
            if root is None:
                self.session.commit()
                raise NotFoundError("Entity not found.")
            nodes[root.id] = root
            frontier = {root.id}
            for _ in range(depth):
                if not frontier or len(nodes) >= max_nodes:
                    break
                links = self.session.execute(
                    select(EntityLink.src_entity, EntityLink.dst_entity)
                    .where(
                        *link_conds,
                        or_(
                            EntityLink.src_entity.in_(frontier),
                            EntityLink.dst_entity.in_(frontier),
                        ),
                    )
                    .order_by(EntityLink.weight.desc(), EntityLink.id)
                    .limit(max_edges + 1)
                ).all()
                if len(links) > max_edges:
                    truncated = True
                wanted = [other for src, dst in links for other in (src, dst) if other not in nodes]
                wanted = list(dict.fromkeys(wanted))
                found = {
                    e.id: e
                    for e in self.session.execute(
                        select(Entity).where(Entity.id.in_(wanted))
                    ).scalars()
                } if wanted else {}  # fmt: skip
                frontier = set()
                for eid in wanted:
                    ent = found.get(eid)
                    if ent is None or ent.type not in allowed_types:
                        continue
                    if len(nodes) >= max_nodes:
                        truncated = True
                        break
                    nodes[eid] = ent
                    frontier.add(eid)
        else:
            conds: list[Any] = [Entity.case_id == case_id]
            if types:
                conds.append(Entity.type.in_(types))
            rows = list(
                self.session.execute(
                    select(Entity)
                    .where(*conds)
                    .order_by(Entity.event_count.desc(), Entity.id)
                    .limit(max_nodes + 1)
                ).scalars()
            )
            if len(rows) > max_nodes:
                truncated = True
                rows = rows[:max_nodes]
            nodes = {e.id: e for e in rows}
        ids = list(nodes)
        edges = (
            list(
                self.session.execute(
                    select(EntityLink)
                    .where(
                        *link_conds,
                        EntityLink.src_entity.in_(ids),
                        EntityLink.dst_entity.in_(ids),
                    )
                    .order_by(EntityLink.weight.desc(), EntityLink.id)
                    .limit(max_edges + 1)
                ).scalars()
            )
            if ids
            else []
        )
        if len(edges) > max_edges:
            truncated = True
            edges = edges[:max_edges]
        self.session.commit()
        return Graph(list(nodes.values()), edges, truncated)


__all__ = ["EntityDetail", "EntityService", "Graph", "write_resolution"]

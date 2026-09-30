"""Case chat index (guide 13.7): chunk + embed a case's events into ``event_chunks`` (pgvector),
track freshness in ``ai_index_state``, and retrieve with hybrid search.

Freshness: the index remembers the case's event count and newest ``ingested_at`` at build time;
new, deleted or reprocessed events change one of them, so the index is stale and is rebuilt before
the next chat (under a per-case advisory lock; the state is re-checked after taking the lock, so
concurrent chats rebuild once). Retrieval is always filtered by ``case_id``.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.ai.embeddings import HashingEmbedder
from app.ai.llm import AiUnavailableError
from app.ai.packs import Redact
from app.ai.rag import ChunkDraft, iter_chunks, rrf
from app.config import SCHEMA_EMBEDDING_DIM, Settings
from app.db.models import AiIndexState, Event, EventChunk

BATCH = 200
CANDIDATES = 40
MAX_QUERY_TERMS = 16
TERM_RE = re.compile(r"[a-z0-9][a-z0-9_.\-]{1,62}")
STOPWORDS = frozenset(
    [
        "the",
        "a",
        "an",
        "and",
        "or",
        "of",
        "to",
        "in",
        "on",
        "for",
        "from",
        "with",
        "by",
        "at",
        "is",
        "was",
        "were",
        "are",
        "be",
        "been",
        "did",
        "do",
        "does",
        "what",
        "which",
        "who",
        "whom",
        "when",
        "where",
        "why",
        "how",
        "any",
        "all",
        "this",
        "that",
        "these",
        "those",
        "there",
        "it",
        "its",
        "as",
        "into",
        "about",
        "show",
        "me",
        "list",
        "find",
        "tell",
    ]
)
PACK_COLUMNS = (
    "id",
    "ts",
    "host",
    "user",
    "source_type",
    "event_code",
    "event_category",
    "action",
    "outcome",
    "process_name",
    "pid",
    "ppid",
    "cmdline",
    "file_path",
    "file_hash",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "registry_key",
    "attack_tags",
    "message",
)


def event_columns() -> list[Any]:
    return [getattr(Event, c) for c in PACK_COLUMNS]


def row_map(row: Any) -> dict[str, Any]:
    return {c: getattr(row, c) for c in PACK_COLUMNS}


@dataclass(frozen=True)
class IndexInfo:
    case_id: uuid.UUID
    built_at: datetime | None
    event_count: int
    chunk_count: int
    embedding_model: str | None
    truncated: bool
    stale: bool
    current_event_count: int
    rebuilt: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": str(self.case_id),
            "built_at": self.built_at.isoformat() if self.built_at else None,
            "event_count": self.event_count,
            "chunk_count": self.chunk_count,
            "embedding_model": self.embedding_model,
            "truncated": self.truncated,
            "stale": self.stale,
            "current_event_count": self.current_event_count,
            "rebuilt": self.rebuilt,
        }


def query_terms(question: str) -> list[str]:
    seen: list[str] = []
    for t in TERM_RE.findall(question.lower()):
        t = t.strip(".-")
        if len(t) >= 2 and t not in STOPWORDS and t not in seen:
            seen.append(t)
    return seen[:MAX_QUERY_TERMS]


class AiIndexService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        remote_embed: Callable[[list[str]], list[list[float]]] | None = None,
        redact: Redact | None = None,
    ) -> None:
        self.session = session
        self.settings = settings
        self.remote_embed = remote_embed
        # Redaction of raw values for a hosted embedding provider (None = local, not needed).
        self.redact = redact
        self.local = HashingEmbedder(SCHEMA_EMBEDDING_DIM)

    @property
    def model(self) -> str:
        return self.settings.embedding_model

    def _embed(self, texts: list[str]) -> list[list[float] | None]:
        if self.settings.embedding_provider == "hashing":
            return self.local.embed(texts)
        if self.remote_embed is None:
            raise AiUnavailableError("The embedding provider is not available.")
        vectors = self.remote_embed(texts)
        if len(vectors) != len(texts) or any(len(v) != SCHEMA_EMBEDDING_DIM for v in vectors):
            raise AiUnavailableError(
                f"The embedding provider returned vectors that are not {SCHEMA_EMBEDDING_DIM}-d."
            )
        return list(vectors)

    # ------------------------------------------------------------------ freshness

    def _current(self, case_id: uuid.UUID) -> tuple[int, datetime | None]:
        count, newest = self.session.execute(
            select(func.count(), func.max(Event.ingested_at)).where(Event.case_id == case_id)
        ).one()
        return int(count), newest

    def info(self, case_id: uuid.UUID, *, rebuilt: bool = False) -> IndexInfo:
        state = self.session.get(AiIndexState, case_id, populate_existing=True)
        count, newest = self._current(case_id)
        stale = (
            state is None
            or state.event_count != count
            or state.max_ingested_at != newest
            or state.embedding_model != self.model
        )
        return IndexInfo(
            case_id=case_id,
            built_at=state.built_at if state else None,
            event_count=state.event_count if state else 0,
            chunk_count=state.chunk_count if state else 0,
            embedding_model=state.embedding_model if state else None,
            truncated=bool(state and state.truncated),
            stale=stale,
            current_event_count=count,
            rebuilt=rebuilt,
        )

    def ensure_fresh(self, case_id: uuid.UUID) -> IndexInfo:
        current = self.info(case_id)
        if not current.stale:
            return current
        return self.rebuild(case_id, only_if_stale=True)

    # ------------------------------------------------------------------ build

    def _events(self, case_id: uuid.UUID) -> Iterator[Mapping[str, Any]]:
        stmt = (
            select(*event_columns())
            .where(Event.case_id == case_id)
            .order_by(Event.host.nulls_first(), Event.ts, Event.id)
            .limit(self.settings.ai_index_max_events)
            .execution_options(yield_per=2000)
        )
        for row in self.session.execute(stmt):
            yield row_map(row)

    def _insert(self, case_id: uuid.UUID, batch: list[ChunkDraft]) -> None:
        remote = self.settings.embedding_provider != "hashing"
        vectors = self._embed([c.render(self.redact) if remote else c.text for c in batch])
        # Core insert: no ORM identity map growing with the case size.
        self.session.execute(
            insert(EventChunk),
            [
                {
                    "case_id": case_id,
                    "event_ids": list(c.event_ids),
                    "text": c.text,
                    "embedding": vec,
                    "host": c.host,
                    "ts_start": c.ts_start,
                    "ts_end": c.ts_end,
                    "embedding_model": self.model,
                    "content_sha256": c.content_sha256,
                }
                for c, vec in zip(batch, vectors, strict=True)
            ],
        )

    def rebuild(self, case_id: uuid.UUID, *, only_if_stale: bool = False) -> IndexInfo:
        """Rebuild the case's chunks in one transaction under a per-case advisory lock."""
        self.session.commit()  # start clean: the lock is transaction-scoped
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
            {"k": f"dfirbench:ai_index:{case_id}"},
        )
        if only_if_stale:
            again = self.info(case_id)  # another request may have rebuilt meanwhile
            if not again.stale:
                self.session.commit()
                return again
        count, newest = self._current(case_id)
        self.session.execute(delete(EventChunk).where(EventChunk.case_id == case_id))
        chunks = 0
        batch: list[ChunkDraft] = []
        for chunk in iter_chunks(self._events(case_id)):
            batch.append(chunk)
            if len(batch) >= BATCH:
                self._insert(case_id, batch)
                chunks += len(batch)
                batch = []
        if batch:
            self._insert(case_id, batch)
            chunks += len(batch)
        values = {
            "built_at": datetime.now(UTC),
            "event_count": count,
            "max_ingested_at": newest,
            "chunk_count": chunks,
            "embedding_model": self.model,
            "truncated": count > self.settings.ai_index_max_events,
        }
        self.session.execute(
            insert(AiIndexState)
            .values(case_id=case_id, **values)
            .on_conflict_do_update(index_elements=[AiIndexState.case_id], set_=values)
        )
        self.session.commit()
        return self.info(case_id, rebuilt=True)

    # ------------------------------------------------------------------ retrieve

    def retrieve(self, case_id: uuid.UUID, question: str, *, top_k: int) -> list[EventChunk]:
        """Hybrid retrieval (vector + full text, reciprocal rank fusion), case-scoped."""
        rankings: list[list[uuid.UUID]] = []
        remote = self.settings.embedding_provider != "hashing"
        query = self.redact(question, None) if remote and self.redact else question
        vec = self._embed([query])[0]
        if vec is not None:
            self.session.execute(text("SET LOCAL hnsw.iterative_scan = relaxed_order"))
            rankings.append(
                list(
                    self.session.execute(
                        select(EventChunk.id)
                        .where(EventChunk.case_id == case_id, EventChunk.embedding.is_not(None))
                        .order_by(EventChunk.embedding.cosine_distance(vec))
                        .limit(CANDIDATES)
                    ).scalars()
                )
            )
        terms = query_terms(question)
        if terms:
            tsq = func.to_tsquery("simple", " | ".join(f"'{t}'" for t in terms))
            doc = func.to_tsvector("simple", EventChunk.text)
            rankings.append(
                list(
                    self.session.execute(
                        select(EventChunk.id)
                        .where(EventChunk.case_id == case_id, doc.op("@@")(tsq))
                        .order_by(func.ts_rank(doc, tsq).desc(), EventChunk.id)
                        .limit(CANDIDATES)
                    ).scalars()
                )
            )
        ids = rrf(rankings)[:top_k]
        if not ids:
            return []
        rows = {
            c.id: c
            for c in self.session.execute(
                select(EventChunk).where(EventChunk.case_id == case_id, EventChunk.id.in_(ids))
            ).scalars()
        }
        return [rows[i] for i in ids if i in rows]

    def events_for(
        self, case_id: uuid.UUID, chunks: list[EventChunk], *, limit: int
    ) -> list[dict[str, Any]]:
        """The events of the retrieved chunks (reloaded with the case filter), best chunk first."""
        wanted: list[uuid.UUID] = []
        for chunk in chunks:
            for eid in chunk.event_ids:
                if eid not in wanted:
                    wanted.append(eid)
                if len(wanted) >= limit:
                    break
            if len(wanted) >= limit:
                break
        if not wanted:
            return []
        found = {
            row.id: row_map(row)
            for row in self.session.execute(
                select(*event_columns()).where(Event.case_id == case_id, Event.id.in_(wanted))
            )
        }
        return [found[i] for i in wanted if i in found]

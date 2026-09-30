"""Chunking and rank fusion for case chat (guide 13.7). Pure: no DB, no network.

Chunks group the events of one host in a 5-minute window (at most ``MAX_EVENTS`` events or
``MAX_CHARS`` characters); the text uses the evidence-pack line renderer, so it is sanitized the
same way as a prompt. Events must be passed sorted by (host, ts, id).
"""

from __future__ import annotations

import hashlib
from collections.abc import Hashable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from app.ai.packs import event_line, iso

WINDOW = timedelta(minutes=5)
MAX_EVENTS = 40
MAX_CHARS = 4000
FIELD_CHARS = 256


@dataclass
class ChunkDraft:
    host: str | None
    ts_start: datetime
    ts_end: datetime
    event_ids: list[Any] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        header = f"host={self.host or '-'} window={iso(self.ts_start)}..{iso(self.ts_end)}"
        return "\n".join([header, *self.lines])

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.text.encode()).hexdigest()


def iter_chunks(events: Iterable[Mapping[str, Any]]) -> Iterator[ChunkDraft]:
    """Yield finished chunks while streaming the events (bounded memory)."""
    cur: ChunkDraft | None = None
    size = 0
    for ev in events:
        ts: datetime = ev["ts"]
        host = ev.get("host")
        line = event_line(ev, FIELD_CHARS)
        if (
            cur is None
            or host != cur.host
            or ts - cur.ts_start > WINDOW
            or len(cur.event_ids) >= MAX_EVENTS
            or size + len(line) > MAX_CHARS
        ):
            if cur is not None:
                yield cur
            cur = ChunkDraft(host=host, ts_start=ts, ts_end=ts)
            size = 0
        cur.event_ids.append(ev["id"])
        cur.lines.append(line)
        cur.ts_end = max(cur.ts_end, ts)
        size += len(line) + 1
    if cur is not None:
        yield cur


def build_chunks(events: Iterable[Mapping[str, Any]]) -> list[ChunkDraft]:
    return list(iter_chunks(events))


def rrf[K: Hashable](rankings: Sequence[Sequence[K]], k: int = 60) -> list[K]:
    """Reciprocal rank fusion: best first, ties broken by first appearance."""
    scores: dict[K, float] = {}
    order: dict[K, int] = {}
    for ranking in rankings:
        for rank, key in enumerate(ranking):
            scores[key] = scores.get(key, 0.0) + 1.0 / (k + rank + 1)
            order.setdefault(key, len(order))
    return sorted(scores, key=lambda key: (-scores[key], order[key]))

"""Scrape-time metrics from PostgreSQL and Redis (guide 21.4). No FastAPI imports.

Read with the least-privilege role; each section is a short query over small aggregates, and the
result is cached for ``METRICS_CACHE_S`` so frequent scrapes cannot load the database. A section
that fails is reported as ``dfir_metrics_section_up{section="..."} 0`` instead of failing the
scrape. Nothing here is evidence content.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any, Protocol

import structlog
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.metrics import HTTP_LATENCY, HTTP_REQUESTS, Family

log = structlog.stdlib.get_logger("dfirbench.metrics")


# The Celery queues (app/workers/celery_app.py QUEUES; a unit test keeps the two equal). Services
# do not import the worker package.
QUEUES = ("default", "parse", "detect", "ai", "reports")


class QueueInspector(Protocol):
    def llen(self, name: str) -> Any: ...


_SQL: dict[str, str] = {
    "jobs": "SELECT kind, status, count(*) AS n FROM jobs GROUP BY kind, status",
    "job_duration": (
        "SELECT coalesce(parser, kind) AS name, count(*) AS n, "
        "avg(extract(epoch FROM finished_at - started_at)) AS avg_s, "
        "max(extract(epoch FROM finished_at - started_at)) AS max_s "
        "FROM jobs WHERE finished_at > now() - interval '24 hours' AND started_at IS NOT NULL "
        "GROUP BY coalesce(parser, kind)"
    ),
    "events_ingested": (
        "SELECT coalesce(sum(CASE WHEN run_manifest->'counts'->>'inserted' ~ '^[0-9]{1,15}$' "
        "THEN (run_manifest->'counts'->>'inserted')::bigint ELSE 0 END), 0) "
        "FROM jobs WHERE kind = 'parse' AND finished_at > now() - interval '1 hour'"
    ),
    "evidence": "SELECT status, count(*) AS n FROM evidence GROUP BY status",
    "verification_failures": (
        "SELECT action, count(*) AS n FROM custody_log "
        "WHERE action IN ('hash_failed', 'verification_failed') GROUP BY action"
    ),
    "outbound": "SELECT status, count(*) AS n FROM outbound_deliveries GROUP BY status",
    "ai_today": (
        "SELECT count(*) AS calls, coalesce(sum(coalesce(input_tokens, 0) "
        "+ coalesce(output_tokens, 0)), 0) AS tokens, coalesce(sum(cost_usd), 0) AS cost "
        "FROM ai_interactions WHERE created_at >= date_trunc('day', now() AT TIME ZONE 'UTC') "
        "AT TIME ZONE 'UTC'"
    ),
}


class MetricsCollector:
    _cache: tuple[float, list[Family]] | None = None
    _lock = threading.Lock()

    def __init__(
        self,
        session: Session,
        queues: QueueInspector | None,
        *,
        cache_s: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.session = session
        self.queues = queues
        self.cache_s = cache_s
        self.clock = clock

    @classmethod
    def reset_cache(cls) -> None:
        with cls._lock:
            cls._cache = None

    def families(self) -> list[Family]:
        """HTTP metrics (always live) plus the cached database/Redis families."""
        return [HTTP_REQUESTS.family(), HTTP_LATENCY.family(), *self._scraped()]

    def _scraped(self) -> list[Family]:
        now = self.clock()
        with self._lock:
            cached = MetricsCollector._cache
            if cached is not None and now - cached[0] < self.cache_s:
                return cached[1]
            families = self._collect()
            MetricsCollector._cache = (now, families)
            return families

    def _rows(self, name: str) -> list[Any]:
        rows = list(self.session.execute(text(_SQL[name])).all())
        self.session.commit()
        return rows

    def _collect(self) -> list[Family]:
        up = Family("dfir_metrics_section_up", "1 when a metrics section could be read", "gauge")
        out: list[Family] = []
        sections: list[tuple[str, Callable[[], list[Family]]]] = [
            ("jobs", self._jobs),
            ("job_duration", self._job_duration),
            ("events_ingested", self._events),
            ("evidence", self._evidence),
            ("verification_failures", self._verification),
            ("outbound", self._outbound),
            ("ai_today", self._ai),
            ("queues", self._queues),
        ]
        for name, section in sections:
            try:
                out.extend(section())
                up.add(1, {"section": name})
            except Exception as exc:  # noqa: BLE001 - one failing section must not hide the rest
                self.session.rollback()
                log.warning("metrics_section_failed", section=name, error=type(exc).__name__)
                up.add(0, {"section": name})
        out.append(up)
        return out

    def _jobs(self) -> list[Family]:
        fam = Family("dfir_jobs", "Jobs by kind and status", "gauge")
        for row in self._rows("jobs"):
            fam.add(row.n, {"kind": _enum(row.kind), "status": _enum(row.status)})
        return [fam]

    def _job_duration(self) -> list[Family]:
        avg = Family("dfir_job_duration_seconds_avg_24h", "Average job duration (24 h)", "gauge")
        top = Family("dfir_job_duration_seconds_max_24h", "Longest job duration (24 h)", "gauge")
        count = Family("dfir_jobs_finished_24h", "Jobs finished in the last 24 h", "gauge")
        for row in self._rows("job_duration"):
            labels = {"parser": str(row.name)}
            avg.add(float(row.avg_s or 0), labels)
            top.add(float(row.max_s or 0), labels)
            count.add(row.n, labels)
        return [avg, top, count]

    def _events(self) -> list[Family]:
        fam = Family(
            "dfir_events_ingested_1h", "Events inserted by parse jobs (last hour)", "gauge"
        )
        fam.add(float(self._rows("events_ingested")[0][0]))
        return [fam]

    def _evidence(self) -> list[Family]:
        fam = Family("dfir_evidence", "Evidence items by status", "gauge")
        for row in self._rows("evidence"):
            fam.add(row.n, {"status": str(row.status)})
        return [fam]

    def _verification(self) -> list[Family]:
        fam = Family(
            "dfir_custody_verification_failures", "Custody hash/verification failures", "gauge"
        )
        seen = {str(row.action): row.n for row in self._rows("verification_failures")}
        for action in ("hash_failed", "verification_failed"):
            fam.add(seen.get(action, 0), {"action": action})
        return [fam]

    def _outbound(self) -> list[Family]:
        fam = Family("dfir_outbound_deliveries", "Outbound deliveries by status", "gauge")
        for row in self._rows("outbound"):
            fam.add(row.n, {"status": _enum(row.status)})
        return [fam]

    def _ai(self) -> list[Family]:
        row = self._rows("ai_today")[0]
        calls = Family("dfir_ai_calls_today", "AI calls since 00:00 UTC", "gauge")
        tokens = Family("dfir_ai_tokens_today", "AI input+output tokens since 00:00 UTC", "gauge")
        cost = Family("dfir_ai_cost_usd_today", "AI cost (USD) since 00:00 UTC", "gauge")
        calls.add(row.calls)
        tokens.add(row.tokens)
        cost.add(float(row.cost))
        return [calls, tokens, cost]

    def _queues(self) -> list[Family]:
        if self.queues is None:
            raise RuntimeError("no queue inspector")
        fam = Family("dfir_queue_depth", "Celery messages waiting per queue", "gauge")
        for queue in QUEUES:
            fam.add(int(self.queues.llen(queue)), {"queue": queue})
        return [fam]


def _enum(value: object) -> str:
    return str(getattr(value, "value", value))

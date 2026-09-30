"""Static checks on ORM metadata, the baseline migration, the Celery app, and layer boundaries."""

from __future__ import annotations

import ast
from pathlib import Path

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

import app.db.models as models
from app.db.base import Base
from app.workers.celery_app import QUEUES, celery_app
from app.workers.tasks.system import ping

BACKEND = Path(__file__).resolve().parents[2]
APP_DIR = BACKEND / "app"
BASELINE = BACKEND / "alembic" / "versions" / "0001_baseline.py"

CORE_TABLES = {
    # guide 7.2
    "users", "api_keys", "cases", "case_members", "evidence", "custody_log", "jobs", "events",
    "rules", "alerts", "alert_events", "iocs", "entities", "entity_aliases", "entity_links",
    "notes", "reports", "ai_interactions", "event_chunks", "audit_log",
    # guide 7.3
    "playbooks", "playbook_runs", "agents", "agent_tasks", "bookmarks", "saved_queries",
    "integrations", "notifications", "settings", "signing_keys", "anchors",
}  # fmt: skip
# Phase 1 (migration 0002): server-side refresh tokens and hashed MFA recovery codes.
PHASE1_TABLES = {"refresh_tokens", "mfa_recovery_codes"}
# Phase 3 (migration 0006): rule version history and alert lifecycle history (append-only).
PHASE3_TABLES = {"rule_versions", "alert_history"}
PHASE4_TABLES = {"note_versions"}
PHASE5_TABLES = {"bundle_members"}
PHASE7_TABLES = {"ai_index_state"}
ALL_TABLES = (
    CORE_TABLES | PHASE1_TABLES | PHASE3_TABLES | PHASE4_TABLES | PHASE5_TABLES | PHASE7_TABLES
)


def test_metadata_has_every_core_table() -> None:
    assert set(Base.metadata.tables) == ALL_TABLES


def test_all_timestamps_are_timezone_aware() -> None:
    from sqlalchemy import DateTime

    naive = [
        f"{t.name}.{c.name}"
        for t in Base.metadata.tables.values()
        for c in t.columns
        if isinstance(c.type, DateTime) and not c.type.timezone
    ]
    assert naive == []


def test_events_is_partitioned_with_composite_pk() -> None:
    events = Base.metadata.tables["events"]
    assert [c.name for c in events.primary_key.columns] == ["id", "ts"]
    ddl = str(CreateTable(events).compile(dialect=postgresql.dialect()))
    assert "PARTITION BY RANGE (ts)" in ddl
    assert "ts_original" in events.c


def test_event_chunks_embedding_dimension() -> None:
    col = Base.metadata.tables["event_chunks"].c.embedding
    assert col.type.dim == 384  # type: ignore[attr-defined]


def test_append_only_tables_declared() -> None:
    assert models.APPEND_ONLY_TABLES == (
        "custody_log",
        "audit_log",
        "rule_versions",
        "alert_history",
        "note_versions",
        "bundle_members",
    )


def test_baseline_migration_has_integrity_ddl() -> None:
    src = BASELINE.read_text(encoding="utf-8")
    for needle in (
        "CREATE EXTENSION IF NOT EXISTS {ext}",
        '"vector"',
        "forbid_mutation()",
        "BEFORE UPDATE OR DELETE OR TRUNCATE",
        '"custody_log": "custody_no_update"',
        "PARTITION OF events DEFAULT",
        "dfir_ensure_events_partition",
        "ix_events_fts",
        "hnsw",
    ):
        assert needle in src, needle


def test_celery_configuration() -> None:
    conf = celery_app.conf
    assert {q.name for q in conf.task_queues} == set(QUEUES)
    assert conf.task_acks_late is True
    assert conf.task_reject_on_worker_lost is True
    assert conf.worker_prefetch_multiplier == 1
    assert conf.task_serializer == "json"
    assert conf.enable_utc is True


def test_ping_task_runs_eagerly() -> None:
    assert ping.name == "dfirbench.system.ping"
    assert ping.apply().get(timeout=5) == "pong"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_only_custody_service_writes_custody_log() -> None:
    """Guide 6 rule 4: nothing but services/custody.py may create custody rows."""
    offenders: list[str] = []
    for path in APP_DIR.rglob("*.py"):
        rel = path.relative_to(APP_DIR).as_posix()
        if rel in {"services/custody.py", "db/models/evidence.py", "db/models/__init__.py"}:
            continue
        src = path.read_text(encoding="utf-8")
        if "CustodyLog(" in src or "insert(CustodyLog" in src or "into custody_log" in src.lower():
            offenders.append(rel)
    assert offenders == []


def test_services_do_not_import_web_framework_transitively_via_exceptions() -> None:
    mods = _imports(APP_DIR / "core" / "exceptions.py")
    assert not any(m.split(".")[0] in {"fastapi", "starlette"} for m in mods)


def test_layer_boundaries() -> None:
    """Guide section 6: services never import FastAPI; workers never import api; parsers pure."""
    problems: list[str] = []
    for path in APP_DIR.rglob("*.py"):
        rel = path.relative_to(APP_DIR).as_posix()
        mods = _imports(path)
        if rel.startswith(("services/", "parsers/", "detection/", "repositories/")):
            problems += [f"{rel}: {m}" for m in mods if m.split(".")[0] in {"fastapi", "starlette"}]
        if rel.startswith(("workers/", "services/", "parsers/", "detection/")):
            problems += [f"{rel}: {m}" for m in mods if m.startswith("app.api")]
        if rel.startswith(("parsers/", "detection/")):
            problems += [
                f"{rel}: {m}"
                for m in mods
                if m.startswith(("app.db", "sqlalchemy", "requests", "httpx", "app.services"))
            ]
    assert problems == []

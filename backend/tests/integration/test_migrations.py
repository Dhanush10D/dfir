"""Baseline migration against a real PostgreSQL 16 + pgvector (compose or CI service)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import DBAPIError

import app.db.models  # noqa: F401
from app.db.base import Base
from tests.integration.conftest import alembic_config, create_temp_database, drop_temp_database
from tests.unit.test_models_and_workers import CORE_TABLES

pytestmark = pytest.mark.integration


def _seed_evidence(conn: object) -> uuid.UUID:
    c = conn  # type: ignore[assignment]
    case_id = c.execute(  # type: ignore[attr-defined]
        text("INSERT INTO cases (case_number, title) VALUES (:n, 't') RETURNING id"),
        {"n": f"IR-TEST-{uuid.uuid4().hex[:8]}"},
    ).scalar_one()
    ev_id: uuid.UUID = c.execute(  # type: ignore[attr-defined]
        text(
            "INSERT INTO evidence (case_id, label, kind, original_name, storage_uri) "
            "VALUES (:c, 'EV-001', 'log', 'auth.log', 's3://evidence/x/original') RETURNING id"
        ),
        {"c": case_id},
    ).scalar_one()
    return ev_id


def _insert_custody(conn: object, evidence_id: uuid.UUID, seq: int) -> None:
    conn.execute(  # type: ignore[attr-defined]
        text(
            "INSERT INTO custody_log (evidence_id, seq, actor_label, action, prev_hash, "
            "entry_hash, signature, key_id) VALUES (:e, :s, 'tester', 'ingested', :p, :h, 'sig', "
            "'k1')"
        ),
        {"e": evidence_id, "s": seq, "p": "0" * 64, "h": f"{seq:064x}"},
    )


def test_all_core_tables_exist(db_engine: Engine) -> None:
    tables = set(inspect(db_engine).get_table_names())
    assert tables >= CORE_TABLES
    assert "events_default" in tables
    with db_engine.connect() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert version == "0001"


def test_extensions_and_enums(db_engine: Engine) -> None:
    with db_engine.connect() as conn:
        exts = set(conn.execute(text("SELECT extname FROM pg_extension")).scalars())
        enum_rows = conn.execute(
            text(
                "SELECT t.typname, array_agg(e.enumlabel ORDER BY e.enumsortorder) "
                "FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid GROUP BY t.typname"
            )
        ).all()
    assert {"pgcrypto", "citext", "pg_trgm", "vector"} <= exts
    enums = {name: list(labels) for name, labels in enum_rows}
    assert enums["user_role"] == ["admin", "lead", "analyst", "viewer", "auditor"]
    assert enums["severity"] == ["info", "low", "medium", "high", "critical"]
    assert enums["job_status"][-1] == "partial"
    assert "post_incident" in enums["case_status"]
    assert "false_positive" in enums["alert_status"]


def test_custody_log_insert_allowed(db_engine: Engine) -> None:
    with db_engine.begin() as conn:
        ev = _seed_evidence(conn)
        _insert_custody(conn, ev, 1)
        _insert_custody(conn, ev, 2)
        count = conn.execute(
            text("SELECT count(*) FROM custody_log WHERE evidence_id = :e"), {"e": ev}
        ).scalar_one()
    assert count == 2


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE custody_log SET action = 'tampered'",
        "UPDATE custody_log SET action = 'tampered' WHERE false",  # even zero-row updates
        "DELETE FROM custody_log",
        "DELETE FROM custody_log WHERE false",
        "TRUNCATE custody_log",
        "UPDATE audit_log SET action = 'tampered'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
    ],
)
def test_append_only_tables_reject_mutation(db_engine: Engine, statement: str) -> None:
    with db_engine.begin() as conn:
        ev = _seed_evidence(conn)
        _insert_custody(conn, ev, 1)
        conn.execute(text("INSERT INTO audit_log (action) VALUES ('create')"))
    with pytest.raises(DBAPIError, match="append-only"), db_engine.begin() as conn:
        conn.execute(text(statement))
    with db_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM custody_log WHERE action = 'tampered'")
            ).scalar_one()
            == 0
        )


def test_custody_seq_unique_per_evidence(db_engine: Engine) -> None:
    with pytest.raises(DBAPIError), db_engine.begin() as conn:
        ev = _seed_evidence(conn)
        _insert_custody(conn, ev, 1)
        _insert_custody(conn, ev, 1)


def test_events_partitioning(db_engine: Engine) -> None:
    with db_engine.begin() as conn:
        strategy = conn.execute(
            text(
                "SELECT partstrat FROM pg_partitioned_table "
                "WHERE partrelid = 'public.events'::regclass"
            )
        ).scalar_one()
        assert strategy == "r"
        # 2026-03-31 23:30 at UTC-05:00 is 2026-04-01 04:30 UTC -> April partition.
        part = conn.execute(
            text("SELECT dfir_ensure_events_partition('2026-03-31T23:30:00-05:00')")
        ).scalar_one()
        assert part == "events_y2026m04"
        again = conn.execute(
            text("SELECT dfir_ensure_events_partition('2026-04-15T00:00:00Z')")
        ).scalar_one()
        assert again == part
        bound = conn.execute(
            text("SELECT pg_get_expr(relpartbound, oid) FROM pg_class WHERE relname = :p"),
            {"p": part},
        ).scalar_one()
        assert "2026-04-01 00:00:00+00" in bound and "2026-05-01 00:00:00+00" in bound

        case_id = conn.execute(
            text("INSERT INTO cases (case_number, title) VALUES ('IR-PART-1', 't') RETURNING id")
        ).scalar_one()
        ts = datetime(2026, 4, 1, 4, 30, tzinfo=UTC)
        conn.execute(
            text(
                "INSERT INTO events (case_id, ts, ts_original, source_type, message) "
                "VALUES (:c, :ts, '2026-03-31T23:30:00-05:00', 'test', 'hello world')"
            ),
            {"c": case_id, "ts": ts},
        )
        conn.execute(
            text(
                "INSERT INTO events (case_id, ts, source_type) "
                "VALUES (:c, '1999-01-01T00:00:00Z', 'test')"
            ),
            {"c": case_id},
        )
        rows = conn.execute(
            text(
                "SELECT tableoid::regclass::text, ts, ts_original FROM events "
                "WHERE case_id = :c ORDER BY ts"
            ),
            {"c": case_id},
        ).all()
        assert rows[0][0] == "events_default"
        assert rows[1][0] == "events_y2026m04"
        assert rows[1][1] == ts and rows[1][1].tzinfo is not None
        assert rows[1][2] == "2026-03-31T23:30:00-05:00"
        hits = conn.execute(
            text(
                "SELECT count(*) FROM events WHERE to_tsvector('simple'::regconfig, "
                "(COALESCE(message, ''::text) || ' '::text) || COALESCE(cmdline, ''::text)) "
                "@@ to_tsquery('simple', 'hello')"
            )
        ).scalar_one()
        assert hits == 1


def test_pgvector_column_and_hnsw_index(db_engine: Engine) -> None:
    with db_engine.begin() as conn:
        case_id = conn.execute(
            text("INSERT INTO cases (case_number, title) VALUES ('IR-VEC-1', 't') RETURNING id")
        ).scalar_one()
        vec = "[" + ",".join(["0.1"] * 384) + "]"
        conn.execute(
            text(
                "INSERT INTO event_chunks (case_id, event_ids, text, embedding) "
                "VALUES (:c, ARRAY[gen_random_uuid()], 'chunk', CAST(:v AS vector))"
            ),
            {"c": case_id, "v": vec},
        )
        dist = conn.execute(
            text("SELECT embedding <=> CAST(:v AS vector) FROM event_chunks WHERE case_id = :c"),
            {"c": case_id, "v": vec},
        ).scalar_one()
        assert abs(dist) < 1e-6
        idx = conn.execute(
            text("SELECT indexdef FROM pg_indexes WHERE indexname = 'ix_event_chunks_embedding'")
        ).scalar_one()
        assert "hnsw" in idx and "vector_cosine_ops" in idx


def test_models_match_migrated_schema(db_engine: Engine) -> None:
    def include(obj: object, name: str | None, type_: str, *_: object) -> bool:
        return not (type_ == "table" and name is not None and name.startswith("events_"))

    with db_engine.connect() as conn:
        ctx = MigrationContext.configure(
            conn, opts={"compare_type": True, "include_object": include}
        )
        diff = compare_metadata(ctx, Base.metadata)
    assert diff == []


def test_downgrade_and_reupgrade_roundtrip(admin_engine: Engine) -> None:
    db_url = create_temp_database(admin_engine)
    try:
        cfg = alembic_config(db_url)
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")
        command.upgrade(cfg, "head")
    finally:
        drop_temp_database(admin_engine, db_url)

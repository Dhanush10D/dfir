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
from tests.unit.test_models_and_workers import ALL_TABLES

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
    assert tables >= ALL_TABLES
    assert "events_default" in tables
    with db_engine.connect() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert version == "0011"


def test_app_role_privileges(db_engine: Engine) -> None:
    """Migration 0002: dfirbench_app has DML on ordinary tables, SELECT/INSERT on custody/audit."""

    def privileges(table: str) -> set[str]:
        with db_engine.connect() as conn:
            return {
                p
                for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
                if conn.execute(
                    text("SELECT has_table_privilege('dfirbench_app', :t, :p)"),
                    {"t": table, "p": p},
                ).scalar_one()
            }

    assert privileges("custody_log") == {"SELECT", "INSERT"}
    assert privileges("audit_log") == {"SELECT", "INSERT"}
    assert privileges("alembic_version") == {"SELECT"}
    # 0008: evidence rows are never deleted; UPDATE only on the upload/finalize columns.
    assert privileges("evidence") == {"SELECT", "INSERT"}
    assert privileges("bundle_members") == {"SELECT", "INSERT"}
    assert privileges("refresh_tokens") == {"SELECT", "INSERT", "UPDATE", "DELETE"}
    # 0003: the published key copy cannot be rewritten or deleted by the app.
    assert privileges("signing_keys") == {"SELECT", "INSERT"}
    # 0004: events are never rewritten (reprocess deletes and re-inserts); run manifests stay.
    assert privileges("events") == {"SELECT", "INSERT", "DELETE"}
    assert privileges("jobs") == {"SELECT", "INSERT", "UPDATE"}
    assert privileges("events_default") == set()
    # 0009: the AI audit trail is kept; chunks are rebuilt, never rewritten.
    assert privileges("ai_interactions") == {"SELECT", "INSERT"}
    assert privileges("event_chunks") == {"SELECT", "INSERT", "DELETE"}
    assert privileges("ai_index_state") == {"SELECT", "INSERT", "UPDATE"}
    # 0011: reports are never deleted; UPDATE only on the workflow/content columns.
    assert privileges("reports") == {"SELECT", "INSERT"}
    with db_engine.connect() as conn:

        def report_col(c: str) -> bool:
            return bool(
                conn.execute(
                    text("SELECT has_column_privilege('dfirbench_app', 'reports', :c, 'UPDATE')"),
                    {"c": c},
                ).scalar_one()
            )

        assert all(report_col(c) for c in ("title", "sections", "status", "manifest"))
        assert not any(
            report_col(c)
            for c in ("context", "context_sha256", "case_id", "kind", "version", "family_id")
        )
    with db_engine.connect() as conn:
        review_cols = {
            c
            for c in ("accepted", "reviewed_by", "reviewed_at", "review_note", "feedback")
            if conn.execute(
                text(
                    "SELECT has_column_privilege('dfirbench_app', 'ai_interactions', :c, 'UPDATE')"
                ),
                {"c": c},
            ).scalar_one()
        }
        locked_cols = [
            c
            for c in ("output", "model", "status", "prompt_text", "citations", "case_id")
            if conn.execute(
                text(
                    "SELECT has_column_privilege('dfirbench_app', 'ai_interactions', :c, 'UPDATE')"
                ),
                {"c": c},
            ).scalar_one()
        ]
    assert review_cols == {"accepted", "reviewed_by", "reviewed_at", "review_note", "feedback"}
    assert locked_cols == []
    with db_engine.connect() as conn:
        # 0003: the migrating role can SET ROLE to the app role even without superuser.
        assert conn.execute(
            text("SELECT pg_has_role(current_user, 'dfirbench_app', 'MEMBER')")
        ).scalar_one()
    with db_engine.begin() as conn:  # default privileges cover tables created later by the owner
        conn.execute(text("CREATE TABLE later_table (id int)"))
    try:
        assert privileges("later_table") == {"SELECT", "INSERT", "UPDATE", "DELETE"}
    finally:
        with db_engine.begin() as conn:
            conn.execute(text("DROP TABLE later_table"))


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
        # A reviewed AI interaction survives a 0008 round trip (0009 downgrade clears the review).
        from sqlalchemy import create_engine

        engine = create_engine(db_url)
        try:
            with engine.begin() as conn:
                uid = conn.execute(
                    text(
                        "INSERT INTO users (email, display_name) "
                        "VALUES ('r@x.test', 'r') RETURNING id"
                    )
                ).scalar_one()
                iid = conn.execute(
                    text(
                        "INSERT INTO ai_interactions (feature, provider, model, prompt_version, "
                        "input_refs, output) VALUES ('nlq', 'p', 'm', 'v', '{}', '{}') RETURNING id"
                    )
                ).scalar_one()
                conn.execute(
                    text(
                        "UPDATE ai_interactions SET accepted = true, reviewed_by = :u, "
                        "reviewed_at = now() WHERE id = :i"
                    ),
                    {"u": uid, "i": iid},
                )
        finally:
            engine.dispose()
        # Report rows survive the 0011 round trip: a draft, one in review and a signed (sealed)
        # one. The downgrade cannot keep the review trail or the seal, so it returns every report
        # to an unsealed draft; the upgrade's CHECKs then hold again.
        engine = create_engine(db_url)
        try:
            with engine.begin() as conn:
                cid = conn.execute(
                    text(
                        "INSERT INTO cases (case_number, title) VALUES ('IR-RT-1', 'rt') "
                        "RETURNING id"
                    )
                ).scalar_one()
                approver = conn.execute(
                    text(
                        "INSERT INTO users (email, display_name) "
                        "VALUES ('a@x.test', 'a') RETURNING id"
                    )
                ).scalar_one()
                ids = []
                for _ in range(3):
                    ids.append(
                        conn.execute(
                            text(
                                "INSERT INTO reports (id, case_id, kind, version, context, "
                                "family_id, context_sha256) VALUES (gen_random_uuid(), :c, "
                                "'technical', 1, '{}'::jsonb, gen_random_uuid(), "
                                "repeat('0', 64)) RETURNING id"
                            ),
                            {"c": cid},
                        ).scalar_one()
                    )
                _draft_id, review_id, signed_id = ids
                for rid in (review_id, signed_id):
                    conn.execute(
                        text(
                            "UPDATE reports SET status = 'in_review', submitted_by = :u, "
                            "submitted_at = now() WHERE id = :r"
                        ),
                        {"u": uid, "r": rid},
                    )
                conn.execute(
                    text(
                        "UPDATE reports SET status = 'approved', approved_by = :a, "
                        "approved_at = now() WHERE id = :r"
                    ),
                    {"a": approver, "r": signed_id},
                )
                conn.execute(
                    text(
                        "UPDATE reports SET status = 'signed', signed_by = :a, signed_at = now(), "
                        "key_id = 'k1', manifest = '{}'::jsonb, sha256 = repeat('a', 64), "
                        "signature = 'sig', storage_uri = 's3://artifacts/reports/x/' "
                        "WHERE id = :r"
                    ),
                    {"a": approver, "r": signed_id},
                )
        finally:
            engine.dispose()
        command.downgrade(cfg, "0010")
        command.upgrade(cfg, "head")
        engine = create_engine(db_url)
        try:
            with engine.connect() as conn:
                rows = conn.execute(
                    text(
                        "SELECT status, approved_by, submitted_by, sha256, signature, "
                        "storage_uri, manifest, key_id FROM reports WHERE case_id = :c"
                    ),
                    {"c": cid},
                ).all()
        finally:
            engine.dispose()
        assert len(rows) == 3
        assert all(row == ("draft", None, None, None, None, None, None, None) for row in rows)
        command.downgrade(cfg, "0008")
        command.upgrade(cfg, "head")
    finally:
        drop_temp_database(admin_engine, db_url)


def test_emails_are_stored_lower_case(db_engine: Engine) -> None:
    with pytest.raises(DBAPIError, match="ck_users_email_lowercase"), db_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO users (email, display_name) VALUES ('Mixed@Case.test', 'x')")
        )
    with db_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO users (email, display_name) VALUES ('lower@case.test', 'x')")
        )
    with pytest.raises(DBAPIError), db_engine.begin() as conn:  # citext UNIQUE
        conn.execute(
            text("INSERT INTO users (email, display_name) VALUES ('LOWER@case.test', 'x')")
        )


def test_partition_function_as_app_role_moves_default_rows(db_engine: Engine) -> None:
    """0004: the app role creates partitions only through the SECURITY DEFINER function; rows
    that already sit in events_default for that month are moved into the new partition."""
    with db_engine.begin() as conn:
        case_id = conn.execute(
            text("INSERT INTO cases (case_number, title) VALUES ('IR-PART-2', 't') RETURNING id")
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO events (case_id, ts, source_type) "
                "VALUES (:c, '1985-07-15T10:00:00Z', 'test')"
            ),
            {"c": case_id},
        )
        assert (
            conn.execute(
                text("SELECT tableoid::regclass::text FROM events WHERE case_id = :c"),
                {"c": case_id},
            ).scalar_one()
            == "events_default"
        )
    with db_engine.begin() as conn:
        conn.execute(text("SET LOCAL ROLE dfirbench_app"))
        with pytest.raises(DBAPIError, match="permission denied"), conn.begin_nested():
            conn.execute(
                text(
                    "CREATE TABLE events_y1985m08 PARTITION OF events "
                    "FOR VALUES FROM ('1985-08-01') TO ('1985-09-01')"
                )
            )
        part = conn.execute(
            text("SELECT dfir_ensure_events_partition('1985-07-01T00:00:00Z')")
        ).scalar_one()
        assert part == "events_y1985m07"
        where = conn.execute(
            text("SELECT tableoid::regclass::text FROM events WHERE case_id = :c"), {"c": case_id}
        ).scalar_one()
        assert where == "events_y1985m07"
        with pytest.raises(DBAPIError, match="permission denied"), conn.begin_nested():
            conn.execute(text("SELECT 1 FROM events_y1985m07"))
    with db_engine.connect() as conn:
        prosecdef = conn.execute(
            text("SELECT prosecdef FROM pg_proc WHERE proname = 'dfir_ensure_events_partition'")
        ).scalar_one()
        public_exec = conn.execute(
            text(
                "SELECT has_function_privilege('public', "
                "'dfir_ensure_events_partition(timestamptz)', 'EXECUTE')"
            )
        ).scalar_one()
    assert prosecdef is True and public_exec is False


@pytest.mark.parametrize(
    "ts", ["1969-12-31T23:59:59Z", "2000-01-01T00:00:00Z BC", "9999-01-01T00:00:00Z"]
)
def test_partition_function_rejects_outside_window(db_engine: Engine, ts: str) -> None:
    """0005: a direct call by the app role cannot create partitions outside the worker window."""
    with db_engine.begin() as conn:
        conn.execute(text("SET LOCAL ROLE dfirbench_app"))
        with pytest.raises(DBAPIError, match="outside partition window"):
            conn.execute(text("SELECT dfir_ensure_events_partition(:ts)"), {"ts": ts})

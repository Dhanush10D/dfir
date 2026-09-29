"""Browser history (guide 10.3): Chromium ``History`` (Chrome, Edge, Brave, ...) and Firefox
``places.sqlite`` -> visits, downloads and searches.

The SQLite file is hostile input (spec decision 12). It is opened on the read-only scratch copy
with ``mode=ro&immutable=1`` (no journal/WAL/SHM files are created), ``trusted_schema=OFF``,
``cell_size_check=ON``, ``query_only=ON``, ``mmap_size=0``; the tables used must be real tables,
text columns are truncated inside SQL, and a progress handler aborts queries after
``ToolConfig.sqlite_timeout_s``. A Firefox ``-wal`` file is not replayed (backlog). All SQL text
is built from module constants and column names checked against ``PRAGMA table_info``.

Times: Chromium stores WebKit microseconds since 1601, Firefox PRTime microseconds since 1970,
both UTC. One record per row; a zero time is skipped, an impossible one is an error.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from app.parsers.base import Event, ParseContext, ParserInputError, record_cap_reached
from app.parsers.registry import register
from app.parsers.timeconv import Converted, TimestampError, prtime, webkit

SOURCE = "browser"
# SQLite reports schema errors with the (hostile, possibly non-UTF-8) schema text in the message.
SQLITE_ERRORS = (sqlite3.Error, UnicodeDecodeError)
SQLITE_MAGIC = b"SQLite format 3\x00"
URL_MAX = 8192
TITLE_MAX = 1024
CORE_TRANSITIONS = {
    0: "link",
    1: "typed",
    2: "auto_bookmark",
    3: "auto_subframe",
    4: "manual_subframe",
    5: "generated",
    6: "auto_toplevel",
    7: "form_submit",
    8: "reload",
    9: "keyword",
    10: "keyword_generated",
}
FIREFOX_VISIT_TYPES = {
    1: "link",
    2: "typed",
    3: "bookmark",
    4: "embed",
    5: "redirect_permanent",
    6: "redirect_temporary",
    7: "download",
    8: "framed_link",
    9: "reload",
}
CHROME_DOWNLOAD_STATES = {0: "in_progress", 1: "complete", 2: "cancelled", 3: "interrupted"}
DOWNLOAD_COLUMNS = ("target_path", "total_bytes", "state", "danger_type", "tab_url", "mime_type")
DOWNLOAD_TEXT = {"target_path", "tab_url", "mime_type"}

SQL_CHROME_VISITS = (
    "SELECT v.id, v.visit_time, v.transition, v.from_visit, v.visit_duration, "  # nosec B608
    f"substr(u.url, 1, {URL_MAX}), substr(u.title, 1, {TITLE_MAX}), u.visit_count "
    "FROM visits v LEFT JOIN urls u ON u.id = v.url ORDER BY v.id"
)
SQL_CHROME_CHAIN_URL = (
    f"(SELECT substr(c.url, 1, {URL_MAX}) FROM downloads_url_chains c "  # nosec B608
    "WHERE c.id = d.id ORDER BY c.chain_index LIMIT 1)"
)
SQL_CHROME_SEARCHES = (
    f"SELECT k.url_id, u.last_visit_time, substr(k.term, 1, {TITLE_MAX}), "  # nosec B608
    f"substr(u.url, 1, {URL_MAX}) FROM keyword_search_terms k "
    "LEFT JOIN urls u ON u.id = k.url_id ORDER BY k.url_id"
)
SQL_FIREFOX_VISITS = (
    f"SELECT v.id, v.visit_date, v.visit_type, substr(p.url, 1, {URL_MAX}), "  # nosec B608
    f"substr(p.title, 1, {TITLE_MAX}), p.visit_count FROM moz_historyvisits v "
    "LEFT JOIN moz_places p ON p.id = v.place_id ORDER BY v.id"
)
SQL_FIREFOX_DOWNLOADS = (
    f"SELECT a.id, a.dateAdded, substr(a.content, 1, {URL_MAX}), "  # nosec B608
    f"substr(p.url, 1, {URL_MAX}) FROM moz_annos a "
    "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id "
    "LEFT JOIN moz_places p ON p.id = a.place_id "
    "WHERE n.name = 'downloads/destinationFileURI' ORDER BY a.id"
)


def open_readonly(path: Path, timeout_s: int) -> sqlite3.Connection:
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True, isolation_level=None, check_same_thread=True)
    except SQLITE_ERRORS as exc:
        raise ParserInputError(f"cannot open SQLite database: {type(exc).__name__}") from exc
    deadline = time.monotonic() + timeout_s

    def guard() -> int:
        return 1 if time.monotonic() > deadline else 0

    conn.set_progress_handler(guard, 10_000)
    conn.text_factory = lambda raw: raw.decode("utf-8", "replace")  # hostile text is not UTF-8
    try:
        for pragma in (
            "PRAGMA trusted_schema=OFF",
            "PRAGMA cell_size_check=ON",
            "PRAGMA query_only=ON",
            "PRAGMA mmap_size=0",
        ):
            conn.execute(pragma)
    except SQLITE_ERRORS as exc:
        conn.close()
        raise ParserInputError(f"SQLite database unusable: {exc}") from exc
    return conn


def tables(conn: sqlite3.Connection) -> set[str]:
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' LIMIT 10000"
        ).fetchall()
    except SQLITE_ERRORS as exc:
        raise ParserInputError(f"SQLite schema unreadable: {exc}") from exc
    return {str(r[0]).lower() for r in rows if isinstance(r[0], str)}


def columns(conn: sqlite3.Connection, table: str) -> set[str]:
    # ``table`` is one of our constants (never evidence data); PRAGMA takes no parameters.
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except SQLITE_ERRORS:
        return set()
    return {str(r[1]).lower() for r in rows}


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str(value: Any) -> str | None:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return value if isinstance(value, str) and value else None


class _Rows:
    """Runs one query and turns each row into a record."""

    def __init__(self, ctx: ParseContext, conn: sqlite3.Connection, flavor: str) -> None:
        self.ctx = ctx
        self.conn = conn
        self.flavor = flavor

    def run(
        self,
        label: str,
        sql: str,
        convert: Callable[[int], Converted | None],
        build: Callable[[tuple[Any, ...], Converted], Event],
    ) -> Iterator[Event]:
        stats = self.ctx.stats
        try:
            cursor = self.conn.execute(sql)
        except SQLITE_ERRORS as exc:
            stats.warn("query_failed", label, str(exc)[:200])
            stats.assumptions["incomplete"] = "query_failed"
            return
        n = 0
        while True:
            try:
                row = cursor.fetchone()
            except SQLITE_ERRORS as exc:
                stats.read()
                stats.error(f"{label} after row {n}", "database_error", str(exc)[:200])
                stats.assumptions["incomplete"] = "database_error"
                return
            if row is None:
                return
            if record_cap_reached(self.ctx):
                return
            n += 1
            stats.read()
            location = f"{label} row {row[0]}"
            raw_ts = _int(row[1])
            if raw_ts is None:
                stats.error(location, "bad_timestamp", "not an integer")
                continue
            try:
                converted = convert(raw_ts)
            except TimestampError as exc:
                stats.error(location, "bad_timestamp", str(exc))
                continue
            if converted is None:
                stats.skip(location, "no_timestamp")
                continue
            if n % 1000 == 0:
                self.ctx.progress(0.5)
            yield build(row, converted)

    def event(
        self, kind: str, row_id: Any, ts: Converted, message: str, raw: dict[str, Any], **kw: Any
    ) -> Event:
        return Event(
            ts=ts.ts,
            ts_original=ts.original,
            source_type=SOURCE,
            message=message,
            record_key=f"{kind}:{row_id}",
            source_record_id=f"{kind}:{row_id}",
            source_file=self.ctx.source_file,
            host=self.ctx.host_hint,
            event_category="web",
            action=kind,
            raw={"browser": self.flavor, **raw},
            **kw,
        )


def _chromium(rows: _Rows, conn: sqlite3.Connection, present: set[str]) -> Iterator[Event]:
    def visit(row: tuple[Any, ...], ts: Converted) -> Event:
        transition = _int(row[2]) or 0
        core = CORE_TRANSITIONS.get(transition & 0xFF, str(transition & 0xFF))
        url = _str(row[5])
        return rows.event(
            "visit",
            row[0],
            ts,
            f"Visited {url or '?'}",
            {
                "url": url,
                "title": _str(row[6]),
                "transition": core,
                "transition_raw": transition,
                "from_visit": _int(row[3]),
                "visit_duration_us": _int(row[4]),
                "visit_count": _int(row[7]),
            },
            tags=["typed_url"] if core == "typed" else [],
        )

    yield from rows.run("visits", SQL_CHROME_VISITS, webkit, visit)
    if "downloads" in present:
        cols = columns(conn, "downloads")
        pick = [c for c in DOWNLOAD_COLUMNS if c in cols]
        select = (
            ", ".join(
                f"substr(d.{c}, 1, {URL_MAX})" if c in DOWNLOAD_TEXT else f"d.{c}" for c in pick
            )
            or "NULL"
        )
        url_sql = SQL_CHROME_CHAIN_URL if "downloads_url_chains" in present else "NULL"
        sql = f"SELECT d.id, d.start_time, {url_sql}, {select} FROM downloads d ORDER BY d.id"  # nosec B608

        def download(row: tuple[Any, ...], ts: Converted) -> Event:
            values = dict(zip(pick, row[3:], strict=False))
            target = _str(values.get("target_path"))
            state = _int(values.get("state"))
            url = _str(row[2]) or _str(values.get("tab_url"))
            return rows.event(
                "download",
                row[0],
                ts,
                f"Downloaded {url or '?'} to {target or '?'}",
                {
                    "url": url,
                    "target_path": target,
                    "state": CHROME_DOWNLOAD_STATES.get(state or 0, state),
                    **{k: v for k, v in values.items() if k not in ("target_path", "state")},
                },
                file_path=target,
                tags=["download"],
            )

        yield from rows.run("downloads", sql, webkit, download)
    if "keyword_search_terms" in present:

        def search(row: tuple[Any, ...], ts: Converted) -> Event:
            term = _str(row[2])
            return rows.event(
                "search",
                row[0],
                ts,
                f"Searched for {term or '?'}",
                {"term": term, "url": _str(row[3])},
                tags=["search"],
            )

        yield from rows.run("searches", SQL_CHROME_SEARCHES, webkit, search)


def _firefox(rows: _Rows, present: set[str]) -> Iterator[Event]:
    def visit(row: tuple[Any, ...], ts: Converted) -> Event:
        vtype = _int(row[2])
        url = _str(row[3])
        kind = FIREFOX_VISIT_TYPES.get(vtype or 0, str(vtype))
        return rows.event(
            "visit",
            row[0],
            ts,
            f"Visited {url or '?'}",
            {"url": url, "title": _str(row[4]), "transition": kind, "visit_count": _int(row[5])},
            tags=["typed_url"] if kind == "typed" else [],
        )

    yield from rows.run("visits", SQL_FIREFOX_VISITS, prtime, visit)
    if {"moz_annos", "moz_anno_attributes"} <= present:

        def download(row: tuple[Any, ...], ts: Converted) -> Event:
            target = _str(row[2])
            url = _str(row[3])
            return rows.event(
                "download",
                row[0],
                ts,
                f"Downloaded {url or '?'} to {target or '?'}",
                {"url": url, "target_path": target},
                file_path=target,
                tags=["download"],
            )

        yield from rows.run("downloads", SQL_FIREFOX_DOWNLOADS, prtime, download)


@register
class BrowserParser:
    name = "browser"
    version = "1.0.0"
    description = "Browser history: Chromium History, Firefox places.sqlite (visits, downloads)"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {"sqlite": sqlite3.sqlite_version}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        if not head.startswith(SQLITE_MAGIC):
            return 0.0
        name = filename.rsplit("/", 1)[-1].lower()
        if name in ("history", "places.sqlite"):
            return 0.9
        if b"CREATE TABLE urls" in head and b"visits" in head:
            return 0.9
        if b"moz_places" in head and b"moz_historyvisits" in head:
            return 0.9
        return 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        size = ctx.path.stat().st_size
        if size > ctx.limits.max_structured_bytes:
            raise ParserInputError(f"database of {size} bytes over the structured-input limit")
        with ctx.path.open("rb") as fh:
            if fh.read(16) != SQLITE_MAGIC:
                raise ParserInputError("not a SQLite database")
        ctx.stats.bytes_read = size
        conn = open_readonly(ctx.path, ctx.tools.sqlite_timeout_s)
        try:
            present = tables(conn)
            if {"urls", "visits"} <= present:
                flavor = "chromium"
            elif {"moz_places", "moz_historyvisits"} <= present:
                flavor = "firefox"
            else:
                raise ParserInputError("SQLite database has no browser history tables")
            ctx.stats.assumptions.update(
                {"timezone": "UTC (WebKit/PRTime)", "browser": flavor, "wal_replayed": False}
            )
            rows = _Rows(ctx, conn, flavor)
            if flavor == "chromium":
                yield from _chromium(rows, conn, present)
            else:
                yield from _firefox(rows, present)
            ctx.progress(1.0)
        finally:
            conn.close()

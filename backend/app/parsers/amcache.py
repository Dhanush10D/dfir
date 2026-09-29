"""Amcache.hve -> executed/installed program evidence (guide 10.3), on the bounded regf reader.

* ``Root\\InventoryApplicationFile\\*`` (Windows 10+): path, SHA-1 (``FileId`` without the
  ``0000`` prefix), size, PE link date, product/publisher/version -> ``amcache_file``;
* ``Root\\InventoryApplication\\*``: installed programs -> ``amcache_program``;
* ``Root\\InventoryDriverBinary\\*``: drivers with SHA-1 -> ``amcache_driver``;
* ``Root\\File\\{volume}\\*`` (Windows 8 / early 10 layout): value ``15`` path, ``101`` SHA-1,
  ``17`` last-modified FILETIME -> ``amcache_file`` (``raw.layout = "legacy"``).

The event time is the entry key's last-write time (when Windows recorded the entry, UTC). Every
entry key examined is one record.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Callable, Iterator
from pathlib import Path, PureWindowsPath
from typing import Any

from app.parsers.base import Event, ParseContext
from app.parsers.regf import Hive, Key
from app.parsers.registry import register
from app.parsers.registry_hive import (
    Emitter,
    basename,
    describe_hive,
    hive_info_event,
    int_value,
    key_time,
    open_hive,
    safe_open,
    str_value,
)
from app.parsers.timeconv import filetime

SOURCE = "amcache"
SHA1_RE = re.compile(r"^(?:0000)?([0-9a-fA-F]{40})$")


def sha1(value: str | None) -> str | None:
    if not value:
        return None
    m = SHA1_RE.match(value.strip())
    return m.group(1).lower() if m else None


def _entries(
    em: Emitter,
    hive: Hive,
    path: str,
    build_one: Callable[[Key], Event | None],
) -> Iterator[Event]:
    base = safe_open(em, hive.root, path)
    if base is None:
        return
    for key in em.walk(base.path, base.subkeys):
        event = em.guarded(key.path, functools.partial(build_one, key))
        if event is not None:
            yield event


def _application_file(em: Emitter) -> Callable[[Key], Event | None]:
    def build(key: Key) -> Event | None:
        path = str_value(key, "LowerCaseLongPath")
        file_id = str_value(key, "FileId")
        if not path and not file_id:
            return None
        digest = sha1(file_id)
        raw: dict[str, Any] = {
            "path": path,
            "sha1": digest,
            "file_id": file_id,
            "name": str_value(key, "Name"),
            "size": int_value(key, "Size") or str_value(key, "Size"),
            "link_date": str_value(key, "LinkDate"),
            "product": str_value(key, "ProductName"),
            "publisher": str_value(key, "Publisher"),
            "version": str_value(key, "Version"),
            "binary_type": str_value(key, "BinaryType"),
            "program_id": str_value(key, "ProgramId"),
            "ts_source": "key_last_written",
        }
        return em.event(
            f"file:{key.name.lower()}",
            key_time(key),
            "amcache_file",
            f"Amcache file entry: {path or raw['name'] or key.name}",
            key.path,
            raw,
            tags=["execution"],
            event_category="process",
            action="file_recorded",
            file_path=path,
            file_hash=digest,
            process_name=basename(path),
        )

    return build


def _application(em: Emitter) -> Callable[[Key], Event | None]:
    def build(key: Key) -> Event | None:
        name = str_value(key, "Name")
        if not name:
            return None
        raw = {
            "name": name,
            "version": str_value(key, "Version"),
            "publisher": str_value(key, "Publisher"),
            "install_date": str_value(key, "InstallDate"),
            "root_dir": str_value(key, "RootDirPath"),
            "source": str_value(key, "Source"),
            "ts_source": "key_last_written",
        }
        return em.event(
            f"program:{key.name.lower()}",
            key_time(key),
            "amcache_program",
            f"Amcache program: {name} {raw['version'] or ''}".strip(),
            key.path,
            raw,
            event_category="package",
            action="installed",
            file_path=raw["root_dir"],
        )

    return build


def _driver(em: Emitter) -> Callable[[Key], Event | None]:
    def build(key: Key) -> Event | None:
        digest = sha1(str_value(key, "DriverId"))
        name = str_value(key, "DriverName")
        raw = {
            "driver_path": key.name,
            "sha1": digest,
            "driver_name": name,
            "company": str_value(key, "DriverCompany"),
            "product": str_value(key, "Product"),
            "last_write_time": str_value(key, "DriverLastWriteTime"),
            "signed": int_value(key, "DriverSigned"),
            "ts_source": "key_last_written",
        }
        return em.event(
            f"driver:{key.name.lower()}",
            key_time(key),
            "amcache_driver",
            f"Amcache driver: {key.name}",
            key.path,
            raw,
            event_category="driver",
            action="driver_recorded",
            file_path=key.name,
            file_hash=digest,
            process_name=name or basename(key.name),
        )

    return build


def _legacy_files(em: Emitter, hive: Hive) -> Iterator[Event]:
    base = safe_open(em, hive.root, "Root\\File")
    if base is None:
        return
    for volume in em.walk(base.path, base.subkeys):
        for key in em.walk(volume.path, volume.subkeys):

            def build(key: Key = key, volume: Key = volume) -> Event | None:
                path = str_value(key, "15")
                digest = sha1(str_value(key, "101"))
                if not path and not digest:
                    return None
                modified = key.value("17")
                modified_ts = None
                if modified is not None and modified.as_int() is not None:
                    conv = filetime(modified.as_int() or 0)
                    modified_ts = conv.ts.isoformat() if conv else None
                raw = {
                    "layout": "legacy",
                    "volume": volume.name,
                    "path": path,
                    "sha1": digest,
                    "product": str_value(key, "0"),
                    "company": str_value(key, "1"),
                    "file_modified": modified_ts,
                    "ts_source": "key_last_written",
                }
                return em.event(
                    f"legacy:{volume.name.lower()}:{key.name.lower()}",
                    key_time(key),
                    "amcache_file",
                    f"Amcache file entry: {path or key.name}",
                    key.path,
                    raw,
                    tags=["execution"],
                    event_category="process",
                    action="file_recorded",
                    file_path=path,
                    file_hash=digest,
                    process_name=basename(path),
                )

            event = em.guarded(key.path, build)
            if event is not None:
                yield event


@register
class AmcacheParser:
    name = "amcache"
    version = "1.0.0"
    description = "Amcache.hve: executed files (SHA-1), installed programs and drivers"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {"regf": "dfirbench-regf 1.0"}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        if head[:4] != b"regf":
            return 0.0
        embedded = head[48:112].decode("utf-16-le", "replace").split("\x00", 1)[0]
        names = {PureWindowsPath(embedded).name.lower(), filename.rsplit("/", 1)[-1].lower()}
        return 0.95 if "amcache.hve" in names else 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        hive = open_hive(ctx)
        try:
            describe_hive(ctx, hive, "amcache")
            em = Emitter(ctx, SOURCE, "Amcache")
            info = hive_info_event(em, hive, "amcache")
            if info is not None:
                yield info
            yield from _entries(em, hive, "Root\\InventoryApplicationFile", _application_file(em))
            ctx.progress(0.4)
            yield from _entries(em, hive, "Root\\InventoryApplication", _application(em))
            yield from _entries(em, hive, "Root\\InventoryDriverBinary", _driver(em))
            ctx.progress(0.7)
            yield from _legacy_files(em, hive)
            ctx.stats.assumptions["keys_visited"] = hive.keys_visited
            ctx.progress(1.0)
        finally:
            hive.close()

"""Windows registry hives (SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat) -> curated artifact events.

Built on the bounded ``regf`` reader (spec decisions 1 and 2). Not a key-per-event dump: one
``hive_info`` event per hive, then the artifacts below. Every artifact entry examined is one record
(emitted, skipped when it holds nothing, or an error with its key path).

* SYSTEM (current control set from ``Select\\Current`` only): services, USBSTOR devices (+ the
  device-property install/arrival/removal times), ShimCache/AppCompatCache (Win7 x64, Win10/11),
  BAM/DAM last execution.
* SOFTWARE: Run/RunOnce (+ Wow6432Node, Policies), Winlogon Shell/Userinit, IFEO ``Debugger``,
  Uninstall entries.
* NTUSER.DAT: Run/RunOnce, UserAssist (ROT13 names, Win7+ and XP data layouts), RunMRU,
  TypedPaths, TypedURLs (+ TypedURLsTime).
* UsrClass.dat / unknown hives: ``hive_info`` only (ShellBags are in the backlog).

Times: key last-write (FILETIME, UTC) unless the artifact carries its own FILETIME. MRU-style
lists only know the key's write time, which belongs to the most recent entry; the others are
emitted with that time, ``raw.ts_source = "key_last_written"`` and the tag ``time_inferred``.
"""

from __future__ import annotations

import codecs
import struct
from collections.abc import Callable, Iterator
from pathlib import Path, PureWindowsPath
from typing import Any

from app.parsers.base import (
    Event,
    ParseContext,
    ParserInputError,
    decimal_int,
    record_cap_reached,
)
from app.parsers.regf import Hive, HiveLimits, Key, RegfError, Value, hive_kind, utf16z
from app.parsers.registry import register
from app.parsers.timeconv import Converted, TimestampError, filetime

SOURCE = "registry"
ERRORS = (RegfError, TimestampError, struct.error, UnicodeError, ValueError, OverflowError)
MAX_SHIMCACHE = 100_000
START_TYPES = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}
USB_PROPS = {
    "0064": ("usb_first_install", "first install"),
    "0066": ("usb_last_arrival", "last arrival"),
    "0067": ("usb_last_removal", "last removal"),
}
USB_PROP_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
RUN_KEYS_SOFTWARE = (
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
)
RUN_KEYS_NTUSER = (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
)
WINLOGON_DEFAULTS = {
    "shell": {"explorer.exe"},
    "userinit": {"c:\\windows\\system32\\userinit.exe,"},
}


def open_hive(ctx: ParseContext) -> Hive:
    try:
        return Hive(
            ctx.path,
            max_bytes=ctx.limits.max_structured_bytes,
            limits=HiveLimits(max_depth=ctx.limits.max_depth),
        )
    except RegfError as exc:
        raise ParserInputError(str(exc)) from exc


def describe_hive(ctx: ParseContext, hive: Hive, kind: str) -> None:
    stats = ctx.stats
    stats.assumptions.update(
        {
            "timezone": "UTC (FILETIME)",
            "hive_kind": kind,
            "embedded_name": hive.embedded_name[:128],
            "format": f"{hive.major}.{hive.minor}",
            "dirty": hive.dirty,
            "checksum_ok": hive.checksum_ok,
        }
    )
    if hive.dirty:
        stats.warn("hive_dirty", "base block", "sequence numbers differ; logs not replayed")
    if not hive.checksum_ok:
        stats.warn("base_block_checksum_mismatch", "base block")


def key_time(key: Key) -> Converted:
    converted = key.last_written
    if converted is None:
        raise TimestampError("key has no last-write time")
    return converted


def str_value(key: Key, name: str) -> str | None:
    value = key.value(name)
    if value is None:
        return None
    text = value.as_str()
    return text if text else None


def int_value(key: Key, name: str) -> int | None:
    value = key.value(name)
    return None if value is None else value.as_int()


def basename(path: str | None) -> str | None:
    if not path:
        return None
    return PureWindowsPath(path.strip('"')).name or None


class Emitter:
    """Builds events for one hive and does the per-record accounting."""

    def __init__(self, ctx: ParseContext, source_type: str, hive_label: str) -> None:
        self.ctx = ctx
        self.source_type = source_type
        self.hive_label = hive_label

    def event(
        self,
        record_key: str,
        ts: Converted,
        code: str,
        message: str,
        key_path: str,
        raw: dict[str, Any],
        *,
        tags: list[str] | None = None,
        **fields: Any,
    ) -> Event:
        return Event(
            ts=ts.ts,
            ts_original=ts.original,
            source_type=self.source_type,
            message=message,
            record_key=record_key,
            source_record_id=record_key,
            source_file=self.ctx.source_file,
            host=self.ctx.host_hint,
            event_code=code,
            registry_key=f"{self.hive_label}\\{key_path}" if key_path else self.hive_label,
            tags=tags or [],
            raw={"hive": self.hive_label, **raw},
            **fields,
        )

    def guarded(self, location: str, build: Callable[[], Event | None]) -> Event | None:
        """One record: ``build`` returns an event, ``None`` (skip) or raises (error)."""
        stats = self.ctx.stats
        stats.read()
        try:
            event = build()
        except ERRORS as exc:
            stats.error(location[:300], "unreadable", f"{type(exc).__name__}: {str(exc)[:200]}")
            return None
        if event is None:
            stats.skip(location[:300], "empty")
        return event

    def walk(self, location: str, keys: Callable[[], Iterator[Key]]) -> Iterator[Key]:
        """Iterate subkeys; a list that breaks mid-way costs one error record."""
        try:
            for key in keys():
                if record_cap_reached(self.ctx):
                    return
                yield key
        except ERRORS as exc:
            self.ctx.stats.read()
            self.ctx.stats.error(
                location[:300], "list_unreadable", f"{type(exc).__name__}: {str(exc)[:200]}"
            )

    def values(self, location: str, key: Key) -> Iterator[Value]:
        try:
            for value in key.values():
                if record_cap_reached(self.ctx):
                    return
                yield value
        except ERRORS as exc:
            self.ctx.stats.read()
            self.ctx.stats.error(
                location[:300], "values_unreadable", f"{type(exc).__name__}: {str(exc)[:200]}"
            )


def safe_open(em: Emitter, base: Key, path: str) -> Key | None:
    try:
        return base.open(path)
    except ERRORS as exc:
        em.ctx.stats.warn("key_unreadable", path[:200], f"{type(exc).__name__}")
        return None


# ---------------------------------------------------------------------- SYSTEM


def current_control_set(em: Emitter, hive: Hive) -> str:
    select = safe_open(em, hive.root, "Select")
    current = None
    if select is not None:
        try:
            current = int_value(select, "Current")
        except ERRORS:
            current = None
    name = f"ControlSet{current:03d}" if current and 0 < current < 1000 else "ControlSet001"
    em.ctx.stats.assumptions["control_set"] = name
    return name


def _services(em: Emitter, hive: Hive, cs: str) -> Iterator[Event]:
    services = safe_open(em, hive.root, f"{cs}\\Services")
    if services is None:
        return
    for key in em.walk(f"{cs}\\Services", services.subkeys):

        def build(key: Key = key) -> Event | None:
            image = str_value(key, "ImagePath")
            start = int_value(key, "Start")
            type_ = int_value(key, "Type")
            if image is None and start is None and type_ is None:
                return None
            display = str_value(key, "DisplayName")
            account = str_value(key, "ObjectName")
            params = key.subkey("Parameters")
            dll = str_value(params, "ServiceDll") if params is not None else None
            start_name = START_TYPES.get(start, str(start)) if start is not None else "?"
            autostart = start in (0, 1, 2)
            tags = ["service"] + (["autostart"] if autostart else [])
            return em.event(
                f"service:{key.name.lower()}",
                key_time(key),
                "service",
                f"Service {key.name}: {image or '-'} (start={start_name})",
                key.path,
                {
                    "service": key.name,
                    "display_name": display,
                    "image_path": image,
                    "service_dll": dll,
                    "start": start,
                    "start_name": start_name,
                    "type": type_,
                    "account": account,
                },
                tags=tags,
                event_category="configuration",
                action="service_config",
                file_path=dll or image,
                user=account,
            )

        event = em.guarded(key.path, build)
        if event is not None:
            yield event


def _usbstor(em: Emitter, hive: Hive, cs: str) -> Iterator[Event]:
    usbstor = safe_open(em, hive.root, f"{cs}\\Enum\\USBSTOR")
    if usbstor is None:
        return
    for device in em.walk(usbstor.path, usbstor.subkeys):
        for serial in em.walk(device.path, device.subkeys):

            def build(device: Key = device, serial: Key = serial) -> Event | None:
                friendly = str_value(serial, "FriendlyName")
                return em.event(
                    f"usb:{device.name.lower()}:{serial.name.lower()}",
                    key_time(serial),
                    "usb_device",
                    f"USB storage device {friendly or device.name} (serial {serial.name})",
                    serial.path,
                    {"device": device.name, "serial": serial.name, "friendly_name": friendly},
                    tags=["usb"],
                    event_category="device",
                    action="device_seen",
                )

            event = em.guarded(serial.path, build)
            if event is not None:
                yield event
            yield from _usb_properties(em, device, serial)


def _usb_properties(em: Emitter, device: Key, serial: Key) -> Iterator[Event]:
    props = safe_open(em, serial, f"Properties\\{USB_PROP_GUID}")
    if props is None:
        return
    for prop in em.walk(props.path, props.subkeys):
        code_label = USB_PROPS.get(prop.name.lower())
        if code_label is None:
            continue
        code, label = code_label

        def build(prop: Key = prop, code: str = code, label: str = label) -> Event | None:
            value = prop.value("")
            if value is None or len(value.data) < 8:
                return None
            converted = filetime(struct.unpack_from("<Q", value.data, 0)[0])
            if converted is None:
                return None
            return em.event(
                f"usb:{device.name.lower()}:{serial.name.lower()}:{prop.name.lower()}",
                converted,
                code,
                f"USB device {device.name} (serial {serial.name}) {label}",
                prop.path,
                {"device": device.name, "serial": serial.name, "property": prop.name},
                tags=["usb"],
                event_category="device",
                action=code.removeprefix("usb_"),
            )

        event = em.guarded(prop.path, build)
        if event is not None:
            yield event


def shimcache_entries(data: bytes) -> tuple[str, Iterator[tuple[str, int, dict[str, Any]]]]:
    """(format, iterator of (path, filetime, extra)) for Win10/11 and Win7 x64 AppCompatCache."""
    if len(data) < 8:
        raise ValueError("AppCompatCache value too short")
    header = struct.unpack_from("<I", data, 0)[0]
    if header in (0x30, 0x34) and data[header : header + 4] == b"10ts":
        return "win10", _shim_win10(data, header)
    if header == 0xBADC0FEE:
        return "win7x64", _shim_win7(data)
    raise ValueError(f"unsupported AppCompatCache format (header 0x{header:x})")


def _shim_win10(data: bytes, pos: int) -> Iterator[tuple[str, int, dict[str, Any]]]:
    n = 0
    while pos + 12 <= len(data) and n < MAX_SHIMCACHE:
        if data[pos : pos + 4] != b"10ts":
            raise ValueError(f"bad AppCompatCache entry signature at {pos}")
        entry_size = struct.unpack_from("<I", data, pos + 8)[0]
        body = pos + 12
        end = body + entry_size
        if end > len(data) or entry_size < 2:
            raise ValueError(f"AppCompatCache entry overruns the value at {pos}")
        path_len = struct.unpack_from("<H", data, body)[0]
        if body + 2 + path_len + 12 > end:
            raise ValueError(f"AppCompatCache path overruns its entry at {pos}")
        path = data[body + 2 : body + 2 + path_len].decode("utf-16-le", "replace")
        ft = struct.unpack_from("<Q", data, body + 2 + path_len)[0]
        data_len = struct.unpack_from("<I", data, body + 10 + path_len)[0]
        yield path, ft, {"entry_data_bytes": data_len}
        pos = end
        n += 1


def _shim_win7(data: bytes) -> Iterator[tuple[str, int, dict[str, Any]]]:
    count = struct.unpack_from("<I", data, 4)[0]
    if count > MAX_SHIMCACHE:
        raise ValueError(f"AppCompatCache entry count {count} over the limit")
    for i in range(count):
        off = 128 + i * 48
        if off + 48 > len(data):
            raise ValueError(f"AppCompatCache entry {i} beyond the value")
        path_len, _max, _pad, path_off, ft, insert_flags, _shim = struct.unpack_from(
            "<HHIQQII", data, off
        )
        if path_off + path_len > len(data):
            raise ValueError(f"AppCompatCache path {i} beyond the value")
        path = data[path_off : path_off + path_len].decode("utf-16-le", "replace")
        yield path, ft, {"insert_flags": insert_flags, "executed": bool(insert_flags & 2)}


def _shimcache(em: Emitter, hive: Hive, cs: str) -> Iterator[Event]:
    key = safe_open(em, hive.root, f"{cs}\\Control\\Session Manager\\AppCompatCache")
    if key is None:
        return
    try:
        value = key.value("AppCompatCache")
        if value is None:
            return
        fmt, entries = shimcache_entries(value.data)
        key_ts = key_time(key)
    except ERRORS as exc:
        em.ctx.stats.read()
        em.ctx.stats.error(key.path, "shimcache_unreadable", f"{type(exc).__name__}: {exc}")
        return
    em.ctx.stats.assumptions["shimcache_format"] = fmt
    position = 0
    try:
        for path, ft, extra in entries:
            position += 1

            def build(
                path: str = path, ft: int = ft, extra: dict[str, Any] = extra, pos: int = position
            ) -> Event | None:
                converted = filetime(ft)
                raw: dict[str, Any] = {"position": pos, "format": fmt, "path": path, **extra}
                tags = ["shimcache"]
                if converted is None:
                    converted = key_ts
                    raw["ts_source"] = "key_last_written"
                    tags.append("time_inferred")
                else:
                    raw["ts_source"] = "file_last_modified"
                return em.event(
                    f"shimcache:{pos}",
                    converted,
                    "shimcache",
                    f"ShimCache entry #{pos}: {path}",
                    key.path,
                    raw,
                    tags=tags,
                    event_category="file",
                    action="file_seen",
                    file_path=path,
                    process_name=basename(path),
                )

            event = em.guarded(f"{key.path} entry {position}", build)
            if event is not None:
                yield event
    except ERRORS as exc:
        em.ctx.stats.read()
        em.ctx.stats.error(f"{key.path} after entry {position}", "shimcache_truncated", str(exc))
        em.ctx.stats.assumptions["incomplete"] = "shimcache_truncated"


def _bam(em: Emitter, hive: Hive, cs: str) -> Iterator[Event]:
    for service in ("bam", "dam"):
        base = None
        for path in (
            f"Services\\{service}\\State\\UserSettings",
            f"Services\\{service}\\UserSettings",
        ):
            base = safe_open(em, hive.root, f"{cs}\\{path}")
            if base is not None:
                break
        if base is None:
            continue
        for sid_key in em.walk(base.path, base.subkeys):
            for value in em.values(sid_key.path, sid_key):
                if value.type != 3 or len(value.data) < 8:
                    continue  # Version / SequenceNumber (DWORDs): not execution records

                def build(
                    value: Value = value, sid_key: Key = sid_key, service: str = service
                ) -> Event | None:
                    converted = filetime(struct.unpack_from("<Q", value.data, 0)[0])
                    if converted is None:
                        return None
                    return em.event(
                        f"{service}:{sid_key.name.lower()}:{value.name.lower()}",
                        converted,
                        service,
                        f"{service.upper()}: {value.name} last run by {sid_key.name}",
                        sid_key.path,
                        {"sid": sid_key.name, "path": value.name, "service": service},
                        tags=["execution"],
                        event_category="process",
                        action="process_execution",
                        user=sid_key.name,
                        file_path=value.name,
                        process_name=basename(value.name),
                    )

                event = em.guarded(f"{sid_key.path}\\{value.name}", build)
                if event is not None:
                    yield event


def system_artifacts(em: Emitter, hive: Hive) -> Iterator[Event]:
    cs = current_control_set(em, hive)
    yield from _services(em, hive, cs)
    yield from _usbstor(em, hive, cs)
    yield from _shimcache(em, hive, cs)
    yield from _bam(em, hive, cs)


# ---------------------------------------------------------------------- SOFTWARE / NTUSER


def _run_keys(em: Emitter, hive: Hive, paths: tuple[str, ...]) -> Iterator[Event]:
    for path in paths:
        key = safe_open(em, hive.root, path)
        if key is None:
            continue
        for value in em.values(key.path, key):

            def build(value: Value = value, key: Key = key) -> Event | None:
                command = value.as_str()
                if not command:
                    return None
                return em.event(
                    f"run:{key.path.lower()}:{value.name.lower()}",
                    key_time(key),
                    "run_key",
                    f"Run key {key.name}: {value.name or '(default)'} = {command}",
                    key.path,
                    {"value_name": value.name, "command": command, "ts_source": "key_last_written"},
                    tags=["persistence", "attack.t1547.001"],
                    event_category="configuration",
                    action="autostart_entry",
                    cmdline=command,
                    process_name=basename(command.split('" ', 1)[0].split(" /", 1)[0]),
                )

            event = em.guarded(f"{key.path}\\{value.name}", build)
            if event is not None:
                yield event


def _winlogon(em: Emitter, hive: Hive) -> Iterator[Event]:
    key = safe_open(em, hive.root, "Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
    if key is None:
        return
    for name in ("Shell", "Userinit"):

        def build(name: str = name) -> Event | None:
            value = str_value(key, name)
            if value is None:
                return None
            default = value.strip().lower() in WINLOGON_DEFAULTS[name.lower()]
            tags = [] if default else ["persistence", "attack.t1547.004"]
            return em.event(
                f"winlogon:{name.lower()}",
                key_time(key),
                "winlogon",
                f"Winlogon {name} = {value}" + ("" if default else " (non-default)"),
                key.path,
                {"value_name": name, "value": value, "default": default},
                tags=tags,
                event_category="configuration",
                action="autostart_entry",
                cmdline=value,
            )

        event = em.guarded(f"{key.path}\\{name}", build)
        if event is not None:
            yield event


def _ifeo(em: Emitter, hive: Hive) -> Iterator[Event]:
    base = safe_open(
        em, hive.root, "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
    )
    if base is None:
        return
    for key in em.walk(base.path, base.subkeys):
        try:
            debugger = str_value(key, "Debugger")
        except ERRORS:
            debugger = None
        if not debugger:
            continue

        def build(key: Key = key, debugger: str = debugger) -> Event | None:
            return em.event(
                f"ifeo:{key.name.lower()}",
                key_time(key),
                "ifeo_debugger",
                f"IFEO debugger for {key.name}: {debugger}",
                key.path,
                {"image": key.name, "debugger": debugger},
                tags=["persistence", "attack.t1546.012"],
                event_category="configuration",
                action="autostart_entry",
                cmdline=debugger,
                process_name=key.name,
            )

        event = em.guarded(key.path, build)
        if event is not None:
            yield event


def _uninstall(em: Emitter, hive: Hive) -> Iterator[Event]:
    for path in (
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ):
        base = safe_open(em, hive.root, path)
        if base is None:
            continue
        for key in em.walk(base.path, base.subkeys):

            def build(key: Key = key) -> Event | None:
                name = str_value(key, "DisplayName")
                if not name:
                    return None
                raw = {
                    "display_name": name,
                    "version": str_value(key, "DisplayVersion"),
                    "publisher": str_value(key, "Publisher"),
                    "install_date": str_value(key, "InstallDate"),
                    "install_location": str_value(key, "InstallLocation"),
                    "uninstall_string": str_value(key, "UninstallString"),
                    "ts_source": "key_last_written",
                }
                return em.event(
                    f"uninstall:{key.path.lower()}",
                    key_time(key),
                    "installed_program",
                    f"Installed program: {name} {raw['version'] or ''}".strip(),
                    key.path,
                    raw,
                    event_category="package",
                    action="installed",
                    file_path=raw["install_location"],
                )

            event = em.guarded(key.path, build)
            if event is not None:
                yield event


def software_artifacts(em: Emitter, hive: Hive) -> Iterator[Event]:
    yield from _run_keys(em, hive, RUN_KEYS_SOFTWARE)
    yield from _winlogon(em, hive)
    yield from _ifeo(em, hive)
    yield from _uninstall(em, hive)


def _userassist(em: Emitter, hive: Hive) -> Iterator[Event]:
    base = safe_open(
        em, hive.root, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
    )
    if base is None:
        return
    for guid in em.walk(base.path, base.subkeys):
        count = safe_open(em, guid, "Count")
        if count is None:
            continue
        for value in em.values(count.path, count):

            def build(value: Value = value, count: Key = count, guid: Key = guid) -> Event | None:
                name = codecs.decode(value.name, "rot13")
                data = value.data
                if name.startswith("UEME_") or len(data) < 16:
                    return None
                if len(data) >= 68:  # Windows 7+
                    runs, focus_count, focus_ms = struct.unpack_from("<III", data, 4)
                    ft = struct.unpack_from("<Q", data, 60)[0]
                    raw: dict[str, Any] = {"layout": "win7+", "focus_count": focus_count}
                    raw["focus_ms"] = focus_ms
                else:  # XP layout: session, count (+5), last run
                    runs = max(struct.unpack_from("<I", data, 4)[0] - 5, 0)
                    ft = struct.unpack_from("<Q", data, 8)[0]
                    raw = {"layout": "xp"}
                converted = filetime(ft)
                if converted is None:
                    return None
                raw.update({"program": name, "run_count": runs, "guid": guid.name})
                return em.event(
                    f"userassist:{guid.name.lower()}:{value.name.lower()}",
                    converted,
                    "userassist",
                    f"UserAssist: {name} (run count {runs})",
                    count.path,
                    raw,
                    tags=["execution"],
                    event_category="process",
                    action="program_launch",
                    file_path=name,
                    process_name=basename(name),
                )

            event = em.guarded(f"{count.path}\\{value.name}", build)
            if event is not None:
                yield event


def _mru_list(em: Emitter, hive: Hive, path: str, code: str, label: str) -> Iterator[Event]:
    """RunMRU (letters + MRUList) and TypedPaths/TypedURLs (url1 = most recent)."""
    key = safe_open(em, hive.root, path)
    if key is None:
        return
    times: dict[str, Converted] = {}
    if code == "typed_url":
        times_key = safe_open(
            em, hive.root, "Software\\Microsoft\\Internet Explorer\\TypedURLsTime"
        )
        if times_key is not None:
            for value in em.values(times_key.path, times_key):
                if len(value.data) >= 8:
                    try:
                        conv = filetime(struct.unpack_from("<Q", value.data, 0)[0])
                    except ERRORS:
                        conv = None
                    if conv is not None:
                        times[value.name.lower()] = conv
    try:
        order_value = str_value(key, "MRUList") or ""
    except ERRORS:
        order_value = ""
    for value in em.values(key.path, key):
        if value.name.lower() in ("mrulist", "mrulistex"):
            continue

        def build(value: Value = value) -> Event | None:
            text = value.as_str()
            if not text:
                return None
            if code == "runmru":
                text = text.removesuffix("\\1")
                position = order_value.find(value.name) if value.name else -1
            else:
                number = decimal_int("".join(c for c in value.name if c in "0123456789"), 9)
                position = number - 1 if number is not None else -1
            raw: dict[str, Any] = {
                "value_name": value.name,
                "value": text,
                "mru_position": position,
            }
            tags = [label]
            own = times.get(value.name.lower())
            if own is not None:
                ts = own
                raw["ts_source"] = "typed_urls_time"
            else:
                ts = key_time(key)
                raw["ts_source"] = "key_last_written"
                if position != 0:
                    tags.append("time_inferred")
            return em.event(
                f"{code}:{value.name.lower()}",
                ts,
                code,
                f"{label}: {text}",
                key.path,
                raw,
                tags=tags,
                event_category="user_activity",
                action=code,
                cmdline=text if code == "runmru" else None,
                file_path=text if code == "typed_path" else None,
            )

        event = em.guarded(f"{key.path}\\{value.name}", build)
        if event is not None:
            yield event


def ntuser_artifacts(em: Emitter, hive: Hive) -> Iterator[Event]:
    yield from _run_keys(em, hive, RUN_KEYS_NTUSER)
    yield from _userassist(em, hive)
    yield from _mru_list(
        em,
        hive,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
        "runmru",
        "RunMRU",
    )
    yield from _mru_list(
        em,
        hive,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
        "typed_path",
        "TypedPaths",
    )
    yield from _mru_list(
        em, hive, "Software\\Microsoft\\Internet Explorer\\TypedURLs", "typed_url", "TypedURLs"
    )


HIVE_LABELS = {
    "system": "HKLM\\SYSTEM",
    "software": "HKLM\\SOFTWARE",
    "ntuser": "HKCU",
    "usrclass": "HKCU\\Software\\Classes",
    "sam": "HKLM\\SAM",
    "security": "HKLM\\SECURITY",
    "amcache": "Amcache",
}
EXTRACTORS: dict[str, Callable[[Emitter, Hive], Iterator[Event]]] = {
    "system": system_artifacts,
    "software": software_artifacts,
    "ntuser": ntuser_artifacts,
}


def hive_info_event(em: Emitter, hive: Hive, kind: str) -> Event | None:
    def build() -> Event | None:
        converted = hive.last_written
        if converted is None:
            return None
        return em.event(
            "hive_info",
            converted,
            "hive_info",
            f"Registry hive {em.hive_label} ({kind}) last written",
            "",
            {
                "kind": kind,
                "embedded_name": hive.embedded_name,
                "dirty": hive.dirty,
                "format": f"{hive.major}.{hive.minor}",
            },
            event_category="configuration",
            action="hive_written",
        )

    return em.guarded("base block", build)


@register
class RegistryHiveParser:
    name = "registry_hive"
    version = "1.0.0"
    description = (
        "Windows registry hives (SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat): curated artifacts"
    )
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {"regf": "dfirbench-regf 1.0"}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        return 0.8 if head[:4] == b"regf" else 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        hive = open_hive(ctx)
        try:
            kind = hive_kind(hive, ctx.source_file)
            describe_hive(ctx, hive, kind)
            em = Emitter(ctx, SOURCE, HIVE_LABELS.get(kind, "HKEY"))
            info = hive_info_event(em, hive, kind)
            if info is not None:
                yield info
            extractor = EXTRACTORS.get(kind)
            if extractor is not None:
                ctx.progress(0.1)
                yield from extractor(em, hive)
            else:
                ctx.stats.warn("no_curated_artifacts", detail=kind)
            ctx.stats.assumptions["keys_visited"] = hive.keys_visited
            if hive.cycles:
                ctx.stats.warn("key_cycles_skipped", detail=str(hive.cycles))
            ctx.progress(1.0)
        finally:
            hive.close()


__all__ = ["Emitter", "describe_hive", "key_time", "open_hive", "str_value", "utf16z"]

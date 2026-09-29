"""Windows EVTX parser (guide 10.3/10.4) on python-evtx 0.8.1 (pure Python, Apache-2.0).

python-evtx memory-maps the (read-only) scratch copy with ``ACCESS_READ``, so the file is paged in
by the OS chunk by chunk rather than read into Python memory. Each record is rendered to XML by
python-evtx and parsed with ``defusedxml`` (no entity expansion, no external resources).

Accounting (every record is counted, nothing is dropped silently):

* each record header reached is one record read; a record whose XML cannot be rendered or parsed,
  or that has no usable timestamp, is an error with its chunk/offset;
* python-evtx stops a chunk's record walk silently at a corrupt record header, so the records the
  chunk header declares (first..last record number) but that were never reached are counted as
  errors (``records_unreachable``);
* a declared chunk that is missing (truncated file) or has a bad magic counts as one read + one
  error (its records cannot be enumerated); chunks beyond the declared count (dirty logs) are
  parsed when their magic is valid (``inactive_chunk_parsed`` warning);
* checksum mismatches are warnings: the data is still parsed;
* chunk-level losses (missing/bad chunks, unreachable records) set ``assumptions['incomplete']``,
  so the run is reported as ``partial`` (the events that could be read are kept).

``ts`` is ``System/TimeCreated/@SystemTime`` (UTC by definition); ``ts_original`` keeps that value
as rendered by python-evtx. If it is missing or unparseable, the record header FILETIME is used
and a ``timestamp_from_record_header`` warning is counted.
"""

from __future__ import annotations

import importlib.metadata
import ipaddress
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING, Any

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError
from defusedxml.ElementTree import fromstring as safe_fromstring
from Evtx.Evtx import Evtx

from app.parsers.base import Event, ParseContext, ParserInputError, ParseStats
from app.parsers.registry import register

if TYPE_CHECKING:  # type-only import; all XML parsing goes through defusedxml
    from xml.etree.ElementTree import Element  # nosec B405

EVTX_MAGIC = b"ElfFile\x00"
CHUNK_SIZE = 0x10000
HEADER_SIZE = 0x1000
MAX_RECORDS_PER_CHUNK = CHUNK_SIZE // 0x18  # a record is at least 24 bytes
MAX_RAW_XML = 256 * 1024
XML_INVALID = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
PROTOCOLS = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6"}
EMPTY = {"", "-", "%%1793"}  # "-" and the "<value not set>" message id
# <System> children kept as text. 1.0.1: EventRecordID maps to ``event_record_id`` (1.0.0 produced
# ``event_record_i_d`` and left ``source_record_id`` empty, which the record-gap detector needs).
SYSTEM_TEXT_FIELDS = {
    "EventRecordID": "event_record_id",
    "Channel": "channel",
    "Computer": "computer",
    "Level": "level",
    "Task": "task",
    "Opcode": "opcode",
    "Keywords": "keywords",
}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(el: Element | None) -> str | None:
    if el is None or el.text is None:
        return None
    return el.text


def _flatten(el: Element) -> dict[str, Any]:
    """<EventData>/<UserData> -> {Name: value}; unnamed values go to a list under ``_values``."""
    out: dict[str, Any] = {}
    unnamed: list[str | None] = []
    for child in el:
        tag = _local(child.tag)
        if tag == "Data":
            name = child.get("Name")
            if name:
                out[name] = child.text
            else:
                unnamed.append(child.text)
        elif len(child):
            out[tag] = _flatten(child)
        else:
            out[tag] = child.text
    if unnamed:
        out["_values"] = unnamed
    return out


def _val(data: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = data.get(name)
        if isinstance(value, str) and value.strip() not in EMPTY:
            return value.strip()
    return None


def _account(data: dict[str, Any], user: str, domain: str) -> str | None:
    name = _val(data, user)
    if name is None:
        return None
    dom = _val(data, domain)
    return f"{dom}\\{name}" if dom else name


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def _int(value: str | None, *, bits: int = 31) -> int | None:
    if not value:
        return None
    try:
        number = int(value.strip(), 0)
    except ValueError:
        return None
    return number if 0 <= number < 2**bits else None


def _port(value: str | None) -> int | None:
    number = _int(value)
    return number if number is not None and number <= 65535 else None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return PureWindowsPath(path).name or None


def _sysmon_sha256(hashes: str | None) -> str | None:
    if not hashes:
        return None
    for part in hashes.split(","):
        algo, _, value = part.partition("=")
        if algo.strip().upper() == "SHA256" and re.fullmatch(r"[0-9A-Fa-f]{64}", value.strip()):
            return "sha256:" + value.strip().lower()
    return None


def _status_outcome(status: str | None) -> str:
    if status is None:
        return "unknown"
    return "success" if status.lower() in {"0x0", "0x00000000", "0"} else "failure"


# event id -> (category, action, outcome) for the Security channel.
SECURITY_SIMPLE: dict[str, tuple[str, str, str | None]] = {
    "4624": ("authentication", "logon", "success"),
    "4625": ("authentication", "logon", "failure"),
    "4634": ("authentication", "logoff", "success"),
    "4647": ("authentication", "logoff", "success"),
    "4648": ("authentication", "logon_explicit", "success"),
    "4672": ("authentication", "privileged_logon", "success"),
    "4688": ("process", "create", "success"),
    "4689": ("process", "terminate", "success"),
    "4697": ("service", "create", "success"),
    "4698": ("persistence", "scheduled_task_create", "success"),
    "4699": ("persistence", "scheduled_task_delete", "success"),
    "4702": ("persistence", "scheduled_task_update", "success"),
    "4720": ("iam", "user_create", "success"),
    "4722": ("iam", "user_enable", "success"),
    "4723": ("iam", "password_change", None),
    "4724": ("iam", "password_reset", None),
    "4725": ("iam", "user_disable", "success"),
    "4726": ("iam", "user_delete", "success"),
    "4728": ("iam", "group_member_add", "success"),
    "4729": ("iam", "group_member_remove", "success"),
    "4732": ("iam", "group_member_add", "success"),
    "4733": ("iam", "group_member_remove", "success"),
    "4738": ("iam", "user_modify", "success"),
    "4740": ("iam", "user_lockout", "success"),
    "4756": ("iam", "group_member_add", "success"),
    "4757": ("iam", "group_member_remove", "success"),
    "4768": ("authentication", "kerberos_tgt", None),
    "4769": ("authentication", "kerberos_service_ticket", None),
    "4771": ("authentication", "kerberos_preauth", "failure"),
    "4776": ("authentication", "credential_validation", None),
    "5140": ("network", "share_access", "success"),
    "5152": ("network", "connection", "failure"),
    "5156": ("network", "connection", "success"),
    "5157": ("network", "connection", "failure"),
    "1102": ("audit_log", "clear", "success"),
}
LOGON_EVENTS = {"4624", "4625", "4634", "4647"}
TARGET_USER_EVENTS = LOGON_EVENTS | {"4740", "4768", "4769", "4771", "4776"}


def normalize(
    system: dict[str, Any], data: dict[str, Any], user_data: dict[str, Any]
) -> dict[str, Any]:
    """Map one EVTX record to Appendix A fields (pure; unit-tested per event id)."""
    eid = system.get("event_id") or ""
    provider = system.get("provider") or ""
    channel = system.get("channel") or ""
    out: dict[str, Any] = {}
    security = provider == "Microsoft-Windows-Security-Auditing" or channel == "Security"

    if eid == "1102" and (security or provider == "Microsoft-Windows-Eventlog"):
        cleared = user_data.get("LogFileCleared", {}) if isinstance(user_data, dict) else {}
        cleared = cleared if isinstance(cleared, dict) else {}
        out.update(event_category="audit_log", action="clear", outcome="success")
        out["user"] = _account(cleared, "SubjectUserName", "SubjectDomainName")
        out["message"] = f"Security log cleared by {out['user'] or 'unknown'}"
        return out
    if eid == "104" and provider == "Microsoft-Windows-Eventlog":
        cleared = user_data.get("LogFileCleared", {}) if isinstance(user_data, dict) else {}
        cleared = cleared if isinstance(cleared, dict) else {}
        channel_name = _val(cleared, "Channel") or "unknown"
        out.update(event_category="audit_log", action="clear", outcome="success")
        out["user"] = _account(cleared, "SubjectUserName", "SubjectDomainName")
        out["message"] = f"Event log {channel_name} cleared by {out['user'] or 'unknown'}"
        return out
    if eid == "7045" and provider == "Service Control Manager":
        name = _val(data, "ServiceName")
        image = _val(data, "ImagePath")
        out.update(event_category="service", action="create", outcome="success")
        out.update(file_path=image, process_name=_basename(image), user=_val(data, "AccountName"))
        out["message"] = f"Service installed: {name} ({image})"
        return out
    if provider == "Microsoft-Windows-Sysmon":
        return _sysmon(eid, data)
    if eid == "4104" and provider == "Microsoft-Windows-PowerShell":
        out.update(event_category="process", action="script_block", outcome="success")
        out["cmdline"] = _val(data, "ScriptBlockText")
        out["file_path"] = _val(data, "Path")
        out["message"] = "PowerShell script block logged"
        return out
    if not security or eid not in SECURITY_SIMPLE:
        return out

    category, action, outcome = SECURITY_SIMPLE[eid]
    out.update(event_category=category, action=action, outcome=outcome)
    subject = _account(data, "SubjectUserName", "SubjectDomainName")
    target = _account(data, "TargetUserName", "TargetDomainName")
    if eid in TARGET_USER_EVENTS:
        out["user"] = target or subject
    else:
        out["user"] = subject or target
    if target and out["user"] != target:
        out["target_user"] = target
    out["src_ip"] = _ip(_val(data, "IpAddress", "SourceAddress", "ClientAddress"))
    out["src_port"] = _port(_val(data, "IpPort", "SourcePort", "ClientPort"))
    logon_type = _val(data, "LogonType")
    if eid in {"4768", "4769", "4776"}:
        out["outcome"] = _status_outcome(_val(data, "Status"))
    if eid == "4624":
        out["message"] = (
            f"Successful logon for {out['user']} from {out['src_ip'] or '-'} (type {logon_type})"
        )
    elif eid == "4625":
        out["message"] = (
            f"Failed logon for {out['user']} from {out['src_ip'] or '-'} (type {logon_type})"
        )
        out["failure_reason"] = _val(data, "FailureReason")
        out["sub_status"] = _val(data, "SubStatus")
    elif eid in {"4688", "4689"}:
        image = _val(data, "NewProcessName", "ProcessName")
        out.update(file_path=image, process_name=_basename(image))
        out["cmdline"] = _val(data, "CommandLine")
        out["pid"] = _int(_val(data, "NewProcessId" if eid == "4688" else "ProcessId"))
        if eid == "4688":
            out["ppid"] = _int(_val(data, "ProcessId"))
            out["parent_process"] = _val(data, "ParentProcessName")
        verb = "created" if eid == "4688" else "terminated"
        out["message"] = f"Process {verb}: {image or '-'}"
    elif eid == "4697":
        image = _val(data, "ServiceFileName")
        out.update(file_path=image, process_name=_basename(image))
        out["message"] = f"Service installed: {_val(data, 'ServiceName')} ({image})"
    elif eid in {"4698", "4699", "4702"}:
        out["message"] = f"Scheduled task {action.rsplit('_', 1)[-1]}d: {_val(data, 'TaskName')}"
    elif eid in {"4728", "4729", "4732", "4733", "4756", "4757"}:
        member = _val(data, "MemberName", "MemberSid")
        group = target
        out["target_user"] = member
        out["group"] = group
        verb = "added to" if action == "group_member_add" else "removed from"
        out["message"] = f"{member} {verb} group {group} by {subject}"
    elif category == "iam":
        out["message"] = f"Account {action.replace('_', ' ')}: {target} by {subject}"
    elif eid in {"5152", "5156", "5157"}:
        out["dst_ip"] = _ip(_val(data, "DestAddress"))
        out["dst_port"] = _port(_val(data, "DestPort"))
        out["protocol"] = PROTOCOLS.get(_val(data, "Protocol") or "", _val(data, "Protocol"))
        app = _val(data, "Application")
        out.update(file_path=app, process_name=_basename(app))
        verdict = "allowed" if eid == "5156" else "blocked"
        out["message"] = (
            f"Connection {verdict}: {out['src_ip']}:{out['src_port']} -> "
            f"{out['dst_ip']}:{out['dst_port']} ({out['protocol']})"
        )
    elif eid == "5140":
        out["message"] = f"Share {_val(data, 'ShareName')} accessed by {out['user']}"
    elif eid == "4776":
        out["message"] = f"Credential validation for {out['user']}: {out['outcome']}"
    else:
        out["message"] = f"{action.replace('_', ' ').capitalize()} for {out['user']}"
    return out


def _sysmon(eid: str, data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    image = _val(data, "Image")
    out.update(file_path=image, process_name=_basename(image), user=_val(data, "User"))
    out["pid"] = _int(_val(data, "ProcessId"))
    if eid == "1":
        out.update(event_category="process", action="create", outcome="success")
        out["cmdline"] = _val(data, "CommandLine")
        out["ppid"] = _int(_val(data, "ParentProcessId"))
        out["parent_process"] = _val(data, "ParentImage")
        out["file_hash"] = _sysmon_sha256(_val(data, "Hashes"))
        out["message"] = f"Process created: {image}"
    elif eid == "3":
        out.update(event_category="network", action="connect", outcome="success")
        out["src_ip"] = _ip(_val(data, "SourceIp"))
        out["src_port"] = _port(_val(data, "SourcePort"))
        out["dst_ip"] = _ip(_val(data, "DestinationIp"))
        out["dst_port"] = _port(_val(data, "DestinationPort"))
        out["protocol"] = (_val(data, "Protocol") or "").lower() or None
        out["message"] = f"Network connection {image}: -> {out['dst_ip']}:{out['dst_port']}"
    elif eid == "11":
        target = _val(data, "TargetFilename")
        out.update(event_category="file", action="create", outcome="success", file_path=target)
        out["message"] = f"File created: {target}"
    return out


def _record_xml(xml: str, stats: ParseStats, location: str) -> Element:
    if XML_INVALID.search(xml):
        stats.warn("xml_invalid_chars_replaced", location)
        xml = XML_INVALID.sub("�", xml)
    return safe_fromstring(xml, forbid_dtd=True)


def _system(root: Element) -> dict[str, Any]:
    out: dict[str, Any] = {}
    system = next((c for c in root if _local(c.tag) == "System"), None)
    if system is None:
        return out
    for child in system:
        tag = _local(child.tag)
        if tag == "Provider":
            out["provider"] = child.get("Name")
        elif tag == "EventID":
            out["event_id"] = (child.text or "").strip()
            if child.get("Qualifiers"):
                out["qualifiers"] = child.get("Qualifiers")
        elif tag == "TimeCreated":
            out["time_created"] = child.get("SystemTime")
        elif tag == "Execution":
            out["execution"] = {k: v for k, v in child.attrib.items() if v}
        elif tag == "Security":
            out["security_user_id"] = child.get("UserID") or None
        elif tag in SYSTEM_TEXT_FIELDS:
            out[SYSTEM_TEXT_FIELDS[tag]] = _text(child)
    return out


def _parse_system_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:  # SystemTime is UTC by definition
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


@register
class EvtxParser:
    name = "evtx"
    version = "1.0.1"
    description = "Windows XML event logs (.evtx) via python-evtx; Security/System/Sysmon mapping"
    source_types = ("evtx",)

    def tool_versions(self) -> dict[str, str]:
        return {
            "python-evtx": importlib.metadata.version("python-evtx"),
            "defusedxml": importlib.metadata.version("defusedxml"),
        }

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        return 1.0 if head.startswith(EVTX_MAGIC) else 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        size = ctx.path.stat().st_size
        with ctx.path.open("rb") as fh:
            if fh.read(8) != EVTX_MAGIC:
                raise ParserInputError("not an EVTX file (bad file header magic)")
        if size < HEADER_SIZE:
            raise ParserInputError("EVTX file header is truncated")
        try:
            log = Evtx(str(ctx.path))
            log.__enter__()
        except (ValueError, OSError) as exc:
            raise ParserInputError(f"cannot open EVTX: {type(exc).__name__}") from exc
        try:
            yield from self._parse_open(ctx, log, size)
        finally:
            log.__exit__(None, None, None)

    def _parse_open(self, ctx: ParseContext, log: Evtx, size: int) -> Iterator[Event]:
        stats = ctx.stats
        header = log.get_file_header()
        declared = int(header.chunk_count())
        present = (size - HEADER_SIZE) // CHUNK_SIZE
        stats.assumptions.update(
            {
                "timezone": "UTC (EVTX SystemTime is UTC)",
                "chunks_declared": declared,
                "chunks_present": present,
                "dirty": bool(header.is_dirty()),
            }
        )
        if not header.verify():
            stats.warn("file_header_checksum_or_version_mismatch", "file header")
        if header.is_dirty():
            stats.warn("file_dirty", "file header")
        if (size - HEADER_SIZE) % CHUNK_SIZE:
            stats.warn("trailing_partial_chunk", f"offset {HEADER_SIZE + present * CHUNK_SIZE}")
        seen = 0
        for index, chunk in enumerate(header.chunks(include_inactive=True)):
            ctx.progress(index / max(present, 1))
            location = f"chunk {index} (offset {chunk.offset()})"
            active = index < declared
            if not chunk.check_magic():
                if active:
                    stats.read()
                    stats.error(location, "chunk_bad_magic", n=1)
                    stats.assumptions["incomplete"] = "chunk_bad_magic"
                    seen += 1
                continue
            seen += 1 if active else 0
            if not active:
                stats.warn("inactive_chunk_parsed", location)
            if not chunk.verify():
                stats.warn("chunk_checksum_mismatch", location)
            yield from self._chunk_records(ctx, chunk, index, location)
        if seen < declared:
            missing = declared - seen
            stats.read(missing)
            stats.error(
                "end of file", "chunk_missing", f"{missing} declared chunk(s) absent", missing
            )
            stats.assumptions["incomplete"] = "chunk_missing"
        ctx.progress(1.0)

    def _chunk_records(
        self, ctx: ParseContext, chunk: Any, index: int, location: str
    ) -> Iterator[Event]:
        stats = ctx.stats
        try:
            first = int(chunk.log_first_record_number())
            last = int(chunk.log_last_record_number())
            expected: int | None = last - first + 1
        except (ValueError, OverflowError):
            expected = None
        if expected is not None and not 0 < expected <= MAX_RECORDS_PER_CHUNK:
            stats.warn("chunk_record_range_invalid", location)
            expected = None
        got = 0
        last_offset = chunk.offset()
        records = chunk.records()
        while True:
            try:
                record = next(records)
            except StopIteration:
                break
            except Exception as exc:  # noqa: BLE001 - corrupt structure ends this chunk's walk
                stats.warn("chunk_walk_aborted", location, type(exc).__name__)
                break
            got += 1
            stats.read()
            offset = int(record.offset())
            last_offset = offset
            rec_loc = f"chunk {index} record offset {offset}"
            event = self._record(ctx, record, offset, rec_loc)
            if event is not None:
                yield event
        if expected is not None and got < expected:
            missing = expected - got
            stats.read(missing)
            stats.error(
                f"chunk {index} after offset {last_offset}",
                "records_unreachable",
                f"chunk header declares {expected} records, {got} were readable",
                missing,
            )
            stats.assumptions["incomplete"] = "records_unreachable"

    def _record(self, ctx: ParseContext, record: Any, offset: int, loc: str) -> Event | None:
        stats = ctx.stats
        try:
            xml = record.xml()
        except Exception as exc:  # noqa: BLE001 - hostile input: any render failure is one error
            stats.error(loc, "render_failed", type(exc).__name__)
            return None
        try:
            root = _record_xml(xml, stats, loc)
        except (ParseError, DefusedXmlException) as exc:
            # DTD/entity rejections are not ParseErrors; count them per record, don't fail the job.
            stats.error(loc, "xml_invalid", str(exc)[:200] or type(exc).__name__)
            return None
        system = _system(root)
        data_el = next((c for c in root if _local(c.tag) == "EventData"), None)
        user_el = next((c for c in root if _local(c.tag) == "UserData"), None)
        data = _flatten(data_el) if data_el is not None else {}
        user_data = _flatten(user_el) if user_el is not None else {}
        ts = _parse_system_time(system.get("time_created"))
        ts_original = system.get("time_created")
        if ts is None:
            try:
                header_ts = record.timestamp()
            except Exception as exc:  # noqa: BLE001
                stats.error(loc, "no_timestamp", type(exc).__name__)
                return None
            if not isinstance(header_ts, datetime):
                stats.error(loc, "no_timestamp")
                return None
            ts = header_ts if header_ts.tzinfo else header_ts.replace(tzinfo=UTC)
            ts = ts.astimezone(UTC)
            ts_original = f"record header FILETIME {ts.isoformat()}"
            stats.warn("timestamp_from_record_header", loc)
        try:
            mapped = normalize(system, data, user_data)
        except Exception as exc:  # noqa: BLE001 - a mapping bug must not kill the run
            stats.error(loc, "normalize_failed", type(exc).__name__)
            return None
        eid = system.get("event_id") or "?"
        raw: dict[str, Any] = {
            "system": system,
            "event_data": data,
            "record_offset": offset,
        }
        if user_data:
            raw["user_data"] = user_data
        if len(xml) <= MAX_RAW_XML:
            raw["xml"] = xml
        else:
            stats.warn("raw_xml_omitted_too_large", loc)
        extra: dict[str, Any] = {
            k: mapped.pop(k)
            for k in ("target_user", "failure_reason", "sub_status", "parent_process", "group")
            if k in mapped
        }
        if logon_type := _val(data, "LogonType"):
            extra["logon_type"] = logon_type
        if extra:
            raw["normalized"] = {k: v for k, v in extra.items() if v is not None}
        message = mapped.pop("message", None) or _default_message(system, data)
        return Event(
            ts=ts,
            ts_original=ts_original,
            source_type="evtx",
            message=message,
            record_key=f"offset:{offset}",
            source_record_id=system.get("event_record_id"),
            source_file=ctx.source_file,
            host=system.get("computer") or ctx.host_hint,
            event_code=eid,
            raw=raw,
            **{k: v for k, v in mapped.items() if v is not None},
        )


def _default_message(system: dict[str, Any], data: dict[str, Any]) -> str:
    parts = [
        f"{k}={v}"
        for k, v in list(data.items())[:4]
        if isinstance(v, str) and v.strip() not in EMPTY
    ]
    head = f"{system.get('channel') or system.get('provider') or 'EVTX'} {system.get('event_id')}"
    return head + (": " + ", ".join(parts) if parts else "")

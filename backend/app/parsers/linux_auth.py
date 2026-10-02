"""Linux auth.log / secure / syslog parser (guide 10.3 ``linux_auth``). Pure, streaming.

Accepted line formats (plain text or gzip):

* BSD / rsyslog traditional: ``Sep 14 13:42:03 host prog[pid]: message`` (no year, no zone);
* RFC 3339 prefix (rsyslog high precision): ``2026-09-14T13:42:03.123456+02:00 host prog: msg``;
* RFC 5424: ``<34>1 2026-09-14T13:42:03Z host app procid msgid - msg``.

**Time assumptions for BSD lines** (recorded in the run manifest under ``assumptions``):

* Timezone: the job's ``timezone`` parameter (IANA name, default ``UTC``). Ambiguous local times
  (DST fall-back) resolve to the first occurrence (``fold=0``); non-existent times (spring-forward
  gap) are shifted by ``zoneinfo`` semantics. Both are counted as warnings.
* Year: the ``year`` parameter is the year of the FIRST line. Without it, the year is inferred from
  the reference time (evidence ``acquired_at``, else its upload time): the first line gets the
  reference year, or the year before when its month/day lies after the reference month/day. Each
  time the month goes backwards (Dec -> Jan) the year is incremented (``rollovers``). Logs that span
  more than about eleven months are ambiguous; pass ``year`` explicitly. Lines that end up later
  than the reference time are counted as ``timestamp_after_reference`` warnings.

RFC 3339/5424 timestamps carry their own offset; the ``timezone`` parameter is not applied.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from app.parsers.base import (
    Event,
    ParseContext,
    ParserInputError,
    ParseStats,
    decimal_int,
    snippet,
)
from app.parsers.registry import register
from app.parsers.textio import head_text, iter_lines

MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}
BSD_RE = re.compile(
    r"^(?P<ts>(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}(?P<day>\d{1,2}) "
    r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d{1,9}))?) +(?P<host>\S+) ?"
    r"(?P<rest>.*)$"
)
RFC3339 = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:[Zz]|[+-]\d{2}:?\d{2})"
ISO_RE = re.compile(rf"^(?P<ts>{RFC3339}) +(?P<host>\S+) ?(?P<rest>.*)$")
RFC5424_RE = re.compile(
    rf"^<(?P<pri>\d{{1,3}})>1 (?P<ts>{RFC3339}|-) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) "
    r"(?P<msgid>\S+) (?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$"
)
PROG_RE = re.compile(r"^(?P<prog>[^\s:\[\]]{1,128})(?:\[(?P<pid>\d{1,10})\])?: ?(?P<msg>.*)$")
FRAC_RE = re.compile(r"\.(\d{1,9})")

AUTH_PROGRAMS = frozenset(
    {
        "sshd",
        "sudo",
        "su",
        "login",
        "useradd",
        "userdel",
        "usermod",
        "groupadd",
        "groupdel",
        "groupmod",
        "gpasswd",
        "passwd",
        "chpasswd",
        "chage",
        "systemd-logind",
        "gdm-password",
        "polkitd",
        "pkexec",
        "cron",
        "CRON",
        "dropbear",
        "vsftpd",
    }
)

IP = r"(?P<ip>[0-9A-Fa-f:.]{2,45})"


@dataclass(frozen=True)
class Rule:
    code: str
    programs: frozenset[str] | None  # None = any program
    pattern: re.Pattern[str]
    category: str
    action: str
    outcome: str | None
    template: str


def _rule(
    code: str,
    programs: set[str] | None,
    pattern: str,
    category: str,
    action: str,
    outcome: str | None,
    template: str,
) -> Rule:
    return Rule(
        code,
        frozenset(programs) if programs is not None else None,
        re.compile(pattern),
        category,
        action,
        outcome,
        template,
    )


SSH = {"sshd", "dropbear"}
RULES: tuple[Rule, ...] = (
    _rule(
        "ssh_accepted",
        SSH,
        rf"^Accepted (?P<method>\S+) for (?P<user>\S+) from {IP} port (?P<port>\d+)",
        "authentication",
        "logon",
        "success",
        "SSH login accepted for {user} from {ip} ({method})",
    ),
    _rule(
        "ssh_failed",
        SSH,
        rf"^Failed (?P<method>\S+) for (?:(?P<invalid>invalid user) )?(?P<user>\S+) from {IP} "
        r"port (?P<port>\d+)",
        "authentication",
        "logon",
        "failure",
        "SSH login failed for {user} from {ip} ({method})",
    ),
    _rule(
        "ssh_max_auth",
        SSH,
        rf"^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) "
        rf"from {IP} port (?P<port>\d+)",
        "authentication",
        "logon",
        "failure",
        "SSH maximum authentication attempts exceeded for {user} from {ip}",
    ),
    _rule(
        "ssh_invalid_user",
        SSH,
        rf"^Invalid user (?P<user>\S*) from {IP}(?: port (?P<port>\d+))?",
        "authentication",
        "logon",
        "failure",
        "SSH attempt for invalid user {user} from {ip}",
    ),
    _rule(
        "ssh_disconnected",
        SSH,
        rf"^Disconnected from (?:(?:invalid |authenticating )?user (?P<user>\S+) )?{IP} "
        r"port (?P<port>\d+)",
        "authentication",
        "logoff",
        None,
        "SSH session from {ip} disconnected",
    ),
    _rule(
        "pam_session_opened",
        None,
        r"^pam_unix\((?P<service>[^:)]+):session\): session opened for user "
        r"(?P<user>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<by>\S*))?",
        "session",
        "session_open",
        "success",
        "Session opened for {user} ({service})",
    ),
    _rule(
        "pam_session_closed",
        None,
        r"^pam_unix\((?P<service>[^:)]+):session\): session closed for user (?P<user>[^\s(]+)",
        "session",
        "session_close",
        "success",
        "Session closed for {user} ({service})",
    ),
    _rule(
        "pam_auth_failure",
        None,
        r"^pam_unix\((?P<service>[^:)]+):auth\): authentication failure;.*?"
        r"(?:rhost=(?P<ip>\S*))?\s*(?:user=(?P<user>\S*))?\s*$",
        "authentication",
        "logon",
        "failure",
        "Authentication failure for {user} ({service})",
    ),
    _rule(
        "sudo_command",
        {"sudo"},
        r"^\s*(?P<user>\S+) : (?:(?P<fail>[^;]*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
        r"USER=(?P<target>\S+) ;(?: ENV=.*? ;)?(?: COMMAND=(?P<cmd>.*))?$",
        "process",
        "sudo",
        "success",
        "sudo by {user} as {target}: {cmd}",
    ),
    _rule(
        "su_success",
        {"su"},
        r"^(?:Successful su for (?P<target>\S+) by (?P<user>\S+)|\(to (?P<target2>\S+)\) "
        r"(?P<user2>\S+) on (?P<tty>\S+))",
        "authentication",
        "su",
        "success",
        "su to {target} by {user}",
    ),
    _rule(
        "su_failed",
        {"su"},
        r"^FAILED su for (?P<target>\S+) by (?P<user>\S+)",
        "authentication",
        "su",
        "failure",
        "Failed su to {target} by {user}",
    ),
    _rule(
        "user_created",
        {"useradd", "adduser"},
        r"^new user: name=(?P<target>[^,]+), UID=(?P<uid>\d+)",
        "iam",
        "user_create",
        "success",
        "User account {target} created (uid {uid})",
    ),
    _rule(
        "group_created",
        {"useradd", "groupadd", "adduser", "addgroup"},
        r"^new group: name=(?P<group>[^,]+), GID=(?P<gid>\d+)",
        "iam",
        "group_create",
        "success",
        "Group {group} created (gid {gid})",
    ),
    _rule(
        "group_member_added",
        {"usermod", "gpasswd", "useradd"},
        r"^(?:add|adding user) '(?P<target>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'",
        "iam",
        "group_member_add",
        "success",
        "User {target} added to group {group}",
    ),
    _rule(
        "user_deleted",
        {"userdel", "deluser"},
        r"^delete user '(?P<target>[^']+)'",
        "iam",
        "user_delete",
        "success",
        "User account {target} deleted",
    ),
    _rule(
        "password_changed",
        {"passwd", "chpasswd"},
        r"^pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (?P<target>\S+)",
        "iam",
        "password_change",
        "success",
        "Password changed for {target}",
    ),
    _rule(
        "logind_new_session",
        {"systemd-logind"},
        r"^New session (?P<session>\S+) of user (?P<user>[^\s.]+)\.?",
        "session",
        "session_open",
        "success",
        "New login session {session} of user {user}",
    ),
)


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _port(value: str | None) -> int | None:
    number = decimal_int(value, 5)
    return number if number is not None and number <= 65535 else None


def _pid(value: str | None) -> int | None:
    number = decimal_int(value, 10)
    return number if number is not None and number <= 2**31 - 1 else None


def classify(program: str | None, message: str) -> tuple[Rule, dict[str, str]] | None:
    for rule in RULES:
        if rule.programs is not None and (program is None or program not in rule.programs):
            continue
        match = rule.pattern.match(message)
        if match:
            groups = {k: v for k, v in match.groupdict().items() if v is not None}
            return rule, groups
    return None


class YearResolver:
    """Assigns years to BSD timestamps (see module docstring); tracks rollovers."""

    def __init__(self, ctx: ParseContext, tz: ZoneInfo, stats: ParseStats) -> None:
        self.explicit = ctx.year
        self.reference = ctx.reference_time.astimezone(tz) if ctx.reference_time else None
        self.year: int | None = None
        self.prev_month: int | None = None
        self.rollovers = 0
        stats.assumptions.update(
            {
                "year_source": "param" if self.explicit else ctx.reference_source,
                "reference_time": ctx.reference_time.astimezone(UTC).isoformat()
                if ctx.reference_time
                else None,
            }
        )
        self.stats = stats

    def resolve(self, month: int, day: int) -> int | None:
        if self.year is None:
            if self.explicit is not None:
                self.year = self.explicit
            elif self.reference is not None:
                ref = self.reference
                self.year = ref.year if (month, day) <= (ref.month, ref.day) else ref.year - 1
            else:
                return None
            self.stats.assumptions["first_line_year"] = self.year
        elif self.prev_month is not None and month < self.prev_month:
            self.year += 1
            self.rollovers += 1
            self.stats.assumptions["year_rollovers"] = self.rollovers
        self.prev_month = month
        return self.year


def _local_to_utc(naive: datetime, tz: ZoneInfo, stats: ParseStats, location: str) -> datetime:
    local = naive.replace(tzinfo=tz)
    offset = local.utcoffset()
    if offset is None:  # cannot happen with ZoneInfo
        raise ValueError(f"no UTC offset for {naive} in {tz}")
    # fold=0 and fold=1 give different offsets only in a spring-forward gap or a fall-back
    # overlap (PEP 495): everywhere else (every line in UTC) one subtraction is exact.
    if local.replace(fold=1).utcoffset() == offset:
        return (naive - offset).replace(tzinfo=UTC)
    roundtrip = local.astimezone(UTC).astimezone(tz).replace(tzinfo=None)
    if roundtrip != naive:  # in a spring-forward gap
        stats.warn("nonexistent_local_time", location)
    else:
        stats.warn("ambiguous_local_time", location)
    return local.astimezone(UTC)


def parse_iso(value: str) -> datetime:
    """RFC 3339 -> aware UTC datetime (fractions beyond microseconds are truncated)."""
    text = FRAC_RE.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), value, count=1)
    if text[-1] in "zZ":
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no offset")
    return parsed.astimezone(UTC)


@dataclass
class _Parsed:
    ts: datetime
    ts_original: str
    host: str | None
    program: str | None
    pid: int | None
    message: str
    fmt: str
    extra: dict[str, Any]


@register
class LinuxAuthParser:
    name = "linux_auth"
    version = "1.0.0"
    description = "Linux auth.log/secure/syslog (BSD, RFC 3339 and RFC 5424 lines; plain or gzip)"
    source_types = ("auth_log", "syslog")

    def tool_versions(self) -> dict[str, str]:
        return {}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        text = head_text(head)
        if not text or b"\x00" in text[:4096]:
            return 0.0
        lines = [ln for ln in text.decode("utf-8", "replace").splitlines()[:-1] if ln.strip()]
        lines = lines[:20] or text.decode("utf-8", "replace").splitlines()[:1]
        if not lines:
            return 0.0
        hits = sum(
            1 for ln in lines if BSD_RE.match(ln) or ISO_RE.match(ln) or RFC5424_RE.match(ln)
        )
        score = hits / len(lines)
        if score < 0.6:
            return 0.0
        name = filename.lower()
        bonus = 0.1 if re.search(r"(auth|secure|syslog|messages)", name) else 0.0
        return min(0.8 + bonus, 0.95)

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        try:
            tz = ZoneInfo(ctx.timezone)
        except (ValueError, KeyError) as exc:  # validated by the service; defensive
            raise ParserInputError(f"unknown timezone {ctx.timezone!r}") from exc
        stats.assumptions.update(
            {"timezone": ctx.timezone, "timezone_applies_to": "BSD lines without zone/year"}
        )
        years = YearResolver(ctx, tz, stats)
        reference = ctx.reference_time
        for line in iter_lines(ctx.path, ctx.limits, stats, ctx.progress):
            stats.read()
            location = f"line {line.number}"
            if line.too_long:
                stats.error(location, "line_too_long", f"{line.length} bytes")
                continue
            raw_bytes = line.data
            try:
                text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text = raw_bytes.decode("utf-8", "replace")
                stats.warn("invalid_utf8_replaced", location)
            if not text.strip():
                stats.skip(location, "blank")
                continue
            try:
                parsed = self._parse_line(text, tz, years, stats, location)
            except ValueError as exc:
                stats.error(location, "bad_timestamp", f"{exc}; {snippet(text)}")
                continue
            if parsed is None:
                stats.error(location, "unrecognized_format", snippet(text))
                continue
            if reference is not None and parsed.ts > reference + timedelta(days=1):
                stats.warn("timestamp_after_reference", location)
            yield self._event(ctx, line.number, line.offset, text, parsed)
        stats.assumptions["lines"] = stats.records_read

    # ------------------------------------------------------------------ helpers

    def _parse_line(
        self,
        text: str,
        tz: ZoneInfo,
        years: YearResolver,
        stats: ParseStats,
        location: str,
    ) -> _Parsed | None:
        extra: dict[str, Any] = {}
        m = BSD_RE.match(text)
        if m:
            month = MONTHS[m["mon"]]
            day = int(m["day"])
            year = years.resolve(month, day)
            if year is None:
                raise ValueError("no year reference (set the 'year' parameter)")
            frac = (m["frac"] or "")[:6].ljust(6, "0") if m["frac"] else "0"
            naive = datetime(  # noqa: DTZ001 - local wall time, zone applied below
                year, month, day, int(m["h"]), int(m["mi"]), int(m["s"]), int(frac)
            )
            ts = _local_to_utc(naive, tz, stats, location)
            host, rest, fmt = m["host"], m["rest"], "bsd"
            program, pid, message = self._split_program(rest)
            return _Parsed(ts, m["ts"], host, program, pid, message, fmt, extra)
        m = RFC5424_RE.match(text)
        if m:
            if m["ts"] == "-":
                raise ValueError("RFC 5424 line without timestamp")
            ts = parse_iso(m["ts"])
            app = None if m["app"] == "-" else m["app"]
            pid = _pid(m["procid"]) if m["procid"] != "-" else None
            extra = {"pri": int(m["pri"]), "msgid": None if m["msgid"] == "-" else m["msgid"]}
            if m["sd"] != "-":
                extra["structured_data"] = m["sd"]
            host = None if m["host"] == "-" else m["host"]
            return _Parsed(ts, m["ts"], host, app, pid, m["msg"] or "", "rfc5424", extra)
        m = ISO_RE.match(text)
        if m:
            ts = parse_iso(m["ts"])
            program, pid, message = self._split_program(m["rest"])
            return _Parsed(ts, m["ts"], m["host"], program, pid, message, "rfc3339", extra)
        return None

    @staticmethod
    def _split_program(rest: str) -> tuple[str | None, int | None, str]:
        m = PROG_RE.match(rest)
        if not m:
            return None, None, rest
        return m["prog"], _pid(m["pid"]), m["msg"]

    def _event(self, ctx: ParseContext, number: int, offset: int, text: str, p: _Parsed) -> Event:
        program = p.program
        auth = program in AUTH_PROGRAMS or p.message.startswith("pam_")
        raw: dict[str, Any] = {
            "line": text,
            "line_no": number,
            "byte_offset": offset,
            "format": p.fmt,
            "program": program,
            "pid": p.pid,
            **p.extra,
        }
        event = Event(
            ts=p.ts,
            ts_original=p.ts_original,
            source_type="auth_log" if auth else "syslog",
            message=p.message,
            record_key=f"line:{number}",
            source_record_id=str(number),
            source_file=ctx.source_file,
            host=p.host or ctx.host_hint,
            process_name=program,
            pid=p.pid,
            raw=raw,
        )
        found = classify(program, p.message)
        if found is None:
            return event
        rule, g = found
        user = g.get("user") or g.get("user2")
        target = g.get("target") or g.get("target2")
        ip = g.get("ip")
        outcome = rule.outcome
        if rule.code == "sudo_command" and g.get("fail"):
            outcome = "failure"
        values = {
            "user": user or "?",
            "target": target or "?",
            "ip": ip or "?",
            "method": g.get("method", "?"),
            "service": g.get("service", "?"),
            "cmd": g.get("cmd", ""),
            "uid": g.get("uid", "?"),
            "gid": g.get("gid", "?"),
            "group": g.get("group", "?"),
            "session": g.get("session", "?"),
        }
        event.event_code = rule.code
        event.event_category = rule.category
        event.action = rule.action
        event.outcome = outcome
        event.user = user or (target if rule.category == "iam" else None)
        event.src_ip = _ip(ip)
        event.src_port = _port(g.get("port"))
        if g.get("cmd"):
            event.cmdline = g["cmd"]
        event.message = rule.template.format(**values)
        if rule.code == "sudo_command" and g.get("fail"):
            event.message = f"sudo failed for {values['user']} as {values['target']} ({g['fail']})"
        details: dict[str, Any] = {
            k: v for k, v in g.items() if k not in {"user", "ip", "port", "cmd", "fail"}
        }
        if target:
            details["target_user"] = target
        if g.get("invalid"):
            details["invalid_user"] = True
        if g.get("fail"):
            details["failure"] = g["fail"]
        event.raw["auth"] = details
        return event

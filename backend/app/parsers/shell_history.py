"""Shell command history: bash/sh/ash (``#<epoch>`` lines when ``HISTTIMEFORMAT`` was set), zsh
(extended ``: <epoch>:<elapsed>;<command>``), and PowerShell PSReadLine
``ConsoleHost_history.txt`` (guide 10.3 ``bash_history``).

One record per line. A bash timestamp line is metadata for the next command (skipped record);
blank lines are skipped. Commands without a stored time use the evidence reference time
(``raw.ts_source = "reference:..."``, tag ``time_inferred``): history files do not record when
most commands ran, and the order is kept in ``record_key`` / ``raw.line_no``. The user comes from
the collected path (``home/<user>/``, ``users/<user>/``, ``root/``) when present.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from app.parsers.base import Event, ParseContext, record_cap_reached, reference_ts, snippet
from app.parsers.registry import register
from app.parsers.textio import iter_lines
from app.parsers.timeconv import Converted, TimestampError, unix_seconds

SOURCE = "shell_history"
NAMES = {
    ".bash_history": "bash",
    ".zsh_history": "zsh",
    ".sh_history": "sh",
    ".history": "sh",
    ".ash_history": "ash",
    "consolehost_history.txt": "powershell",
}
BASH_TS = re.compile(r"^#([0-9]{9,11})$")
# zsh EXTENDED_HISTORY. Digits are ASCII and bounded (``int()`` refuses > 4300 digits); a line of
# the same shape with oversized numbers is a counted error, not a command.
ZSH_EXT = re.compile(r"^: ([0-9]{1,20}):([0-9]{1,10});(.*)$", re.S)
ZSH_SHAPE = re.compile(r"^: [0-9]+:[0-9]+;")
USER_RE = re.compile(r"(?:^|/)(?:home|users)/([^/]{1,64})/", re.I)


def shell_of(filename: str) -> str | None:
    name = filename.rsplit("/", 1)[-1].lower()
    base = re.sub(r"~\d+$", "", name)  # collector de-duplication suffix
    return NAMES.get(base)


def user_of(filename: str) -> str | None:
    m = USER_RE.search(filename)
    if m:
        return m.group(1)
    if re.search(r"(?:^|/)root/", filename):
        return "root"
    return None


@register
class ShellHistoryParser:
    name = "shell_history"
    version = "1.0.0"
    description = "Shell history: bash/sh/zsh (with timestamps when recorded), PSReadLine"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        if shell_of(filename) is None or b"\x00" in head[:4096]:
            return 0.0
        return 0.7

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        shell = shell_of(ctx.source_file) or "sh"
        user = user_of(ctx.source_file)
        reference, ref_source = reference_ts(ctx)
        stats.assumptions.update({"shell": shell, "user_from_path": user, "undated": ref_source})
        pending: Converted | None = None
        for line in iter_lines(ctx.path, ctx.limits, stats, ctx.progress):
            if record_cap_reached(ctx):
                return
            stats.read()
            location = f"line {line.number}"
            if line.too_long:
                stats.error(location, "line_too_long", f"{line.length} bytes")
                continue
            text = line.data.decode("utf-8", "replace")
            if not text.strip():
                stats.skip(location, "blank")
                continue
            m = BASH_TS.match(text)
            if m and shell != "powershell":
                try:
                    pending = unix_seconds(int(m.group(1)))
                except TimestampError:
                    pending = None
                stats.skip(location, "timestamp_line")
                continue
            command = text
            stamp = pending
            pending = None
            extra: dict[str, int] = {}
            z = ZSH_EXT.match(text)
            if z is None and ZSH_SHAPE.match(text):
                stats.error(location, "bad_zsh_record", snippet(text))
                continue
            if z:
                command = z.group(3)
                extra["elapsed_s"] = int(z.group(2))
                try:
                    stamp = unix_seconds(int(z.group(1)))
                except TimestampError as exc:
                    stats.error(location, "bad_timestamp", f"{exc}; {snippet(text)}")
                    continue
            tags = ["command"]
            if stamp is None:
                ts, original, source = reference, None, ref_source
                tags.append("time_inferred")
            else:
                ts, original, source = stamp.ts, stamp.original, "history_timestamp"
            yield Event(
                ts=ts,
                ts_original=original,
                source_type=SOURCE,
                message=f"{shell}: {command}",
                record_key=f"line:{line.number}",
                source_record_id=str(line.number),
                source_file=ctx.source_file,
                host=ctx.host_hint,
                user=user,
                event_code="shell_command",
                event_category="process",
                action="command",
                cmdline=command,
                process_name=shell,
                tags=tags,
                raw={"line_no": line.number, "shell": shell, "ts_source": source, **extra},
            )

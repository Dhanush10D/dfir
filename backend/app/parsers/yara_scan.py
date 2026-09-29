"""YARA scan of one evidence item with the trusted rule pack (guide 11.4, spec decision 5).

Rules come only from trusted configuration: the packaged pack (``app/detection/yara``) and the
optional operator directory ``ToolConfig.yara_rules_dirs`` (``YARA_RULES_DIR``). They are compiled
with ``includes=False``; the pack SHA-256 (file names + bytes, sorted) and rule count go into the
run manifest. The scan uses a timeout and refuses files above ``yara_max_file_bytes``.

One record per matching rule -> one ``yara`` event. Matches have no intrinsic time: the event uses
the evidence reference time (``raw.ts_source``, tag ``time_inferred``). A scan timeout is one
error and the run is ``partial`` (matches found before it are not reported by libyara).
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yara

from app.parsers.base import Event, ParseContext, ParserInputError, reference_ts
from app.parsers.registry import register

SOURCE = "yara"
PACK_DIR = Path(__file__).resolve().parents[1] / "detection" / "yara"
RULE_SUFFIXES = (".yar", ".yara")
MAX_RULE_FILES = 500
MAX_RULE_BYTES = 16 * 1024 * 1024
MAX_STRINGS = 16
MAX_MATCH_BYTES = 64
NAMESPACE_RE = re.compile(r"[^A-Za-z0-9_]")


def rule_files(extra_dirs: tuple[str, ...]) -> list[tuple[str, Path]]:
    """(namespace, path) for the packaged pack and each trusted extra directory (non-recursive)."""
    found: list[tuple[str, Path]] = []
    dirs = [("pack", PACK_DIR)] + [(f"site{i}", Path(d)) for i, d in enumerate(extra_dirs)]
    total = 0
    for prefix, directory in dirs:
        if not directory.is_dir():
            if prefix != "pack":
                raise ParserInputError(f"YARA_RULES_DIR {directory} is not a directory")
            continue
        for path in sorted(directory.iterdir()):
            if path.suffix.lower() not in RULE_SUFFIXES or not path.is_file() or path.is_symlink():
                continue
            total += path.stat().st_size
            if len(found) >= MAX_RULE_FILES or total > MAX_RULE_BYTES:
                raise ParserInputError("YARA rule set exceeds the file count/size limit")
            found.append((f"{prefix}_{NAMESPACE_RE.sub('_', path.stem)}", path))
    if not found:
        raise ParserInputError("no YARA rules available")
    return found


def compile_rules(extra_dirs: tuple[str, ...]) -> tuple[Any, dict[str, Any]]:
    files = rule_files(extra_dirs)
    digest = hashlib.sha256()
    for namespace, path in files:
        digest.update(namespace.encode() + b"\x00" + path.read_bytes() + b"\x00")
    try:
        rules = yara.compile(
            filepaths={ns: str(path) for ns, path in files}, includes=False, error_on_warning=False
        )
    except yara.Error as exc:
        raise ParserInputError(f"YARA rules do not compile: {str(exc)[:300]}") from exc
    info = {
        "rule_pack_sha256": digest.hexdigest(),
        "rule_files": [ns for ns, _ in files],
        "rules": sum(1 for _ in rules),
    }
    return rules, info


def _meta(meta: dict[str, Any]) -> dict[str, Any]:
    return {
        str(k)[:64]: (v if isinstance(v, int | bool) else str(v)[:256]) for k, v in meta.items()
    }


@register
class YaraScanParser:
    name = "yara_scan"
    version = "1.0.0"
    description = "YARA scan with the trusted rule pack (explicit request only)"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {
            "yara-python": importlib.metadata.version("yara-python"),
            "libyara": str(yara.YARA_VERSION),
        }

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        return 0.0  # never auto-selected; request parsers: ["yara_scan"]

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        size = ctx.path.stat().st_size
        if size > ctx.tools.yara_max_file_bytes:
            raise ParserInputError(f"file of {size} bytes over YARA_MAX_FILE_MB")
        reference, ref_source = reference_ts(ctx)
        rules, info = compile_rules(ctx.tools.yara_rules_dirs)
        stats.assumptions.update({**info, "timeout_s": ctx.tools.yara_timeout_s})
        ctx.progress(0.05)
        try:
            matches = rules.match(str(ctx.path), timeout=ctx.tools.yara_timeout_s)
        except yara.TimeoutError:
            stats.read()
            stats.error("scan", "yara_timeout", f"after {ctx.tools.yara_timeout_s} s")
            stats.assumptions["incomplete"] = "yara_timeout"
            return
        except yara.Error as exc:
            raise ParserInputError(f"YARA scan failed: {str(exc)[:300]}") from exc
        stats.bytes_read = size
        for match in matches:
            stats.read()
            strings: list[dict[str, Any]] = []
            for string in match.strings:
                for instance in string.instances:
                    if len(strings) >= MAX_STRINGS:
                        break
                    strings.append(
                        {
                            "identifier": string.identifier,
                            "offset": int(instance.offset),
                            "length": int(instance.matched_length),
                            "data_hex": bytes(instance.matched_data[:MAX_MATCH_BYTES]).hex(),
                        }
                    )
            meta = _meta(dict(match.meta))
            tags = ["yara", *[str(t)[:64] for t in match.tags], "time_inferred"]
            if isinstance(meta.get("attack"), str):
                tags.append(f"attack.{meta['attack'].lower()}")
            yield Event(
                ts=reference,
                ts_original=None,
                source_type=SOURCE,
                message=f"YARA rule {match.rule} matched {ctx.source_file}"
                + (f": {meta['description']}" if meta.get("description") else ""),
                record_key=f"rule:{match.namespace}:{match.rule}",
                source_record_id=f"{match.namespace}:{match.rule}",
                source_file=ctx.source_file,
                host=ctx.host_hint,
                event_code=str(match.rule),
                event_category="malware",
                action="yara_match",
                outcome="match",
                file_path=ctx.source_file,
                tags=tags,
                raw={
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "meta": meta,
                    "strings": strings,
                    "rule_pack_sha256": info["rule_pack_sha256"],
                    "ts_source": ref_source,
                },
            )
        ctx.progress(1.0)

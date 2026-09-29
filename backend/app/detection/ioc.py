"""IOC normalization, import parsing (CSV, JSON, STIX 2.1 subset) and matching (guide 11.4).

Values are normalized before storage and before matching: defanged forms (``hxxp``, ``[.]``,
``(dot)``) are refanged, domains/e-mails/hashes are lower-cased, IPs are canonical, URLs get a
lower-case scheme and host. Matching is exact on normalized values:

=========  ==========================================================================
type       compared against
=========  ==========================================================================
ip         ``src_ip``, ``dst_ip``
domain     host names found in ``cmdline``/``message`` (and URLs there); a domain IOC also
           matches its sub-domains
url        URLs found in ``cmdline``/``message``
sha256/    ``file_hash`` (``sha256:<hex>`` or bare hex)
sha1/md5
email      addresses found in ``user``/``message``/``cmdline``
filename   base name of ``file_path`` and ``process_name`` (case-insensitive)
=========  ==========================================================================

Extraction uses fixed, linear regular expressions over text that is already bounded (32 KiB).
"""

from __future__ import annotations

import contextlib
import csv
import io
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

IOC_TYPES = ("ip", "domain", "url", "sha256", "sha1", "md5", "email", "filename")
TLP = ("clear", "white", "green", "amber", "amber+strict", "red")
HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}
MAX_VALUE = 2048
MAX_IMPORT_ITEMS = 10_000
MAX_IMPORT_BYTES = 2 * 1024 * 1024

HEX = re.compile(r"^[0-9a-f]+$")
DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,62}$"
)
EMAIL = re.compile(r"^[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}$")
HOST_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9_-]{1,63}\.){1,10}[A-Za-z][A-Za-z0-9-]{1,62}(?![A-Za-z0-9_-])"
)
URL_TOKEN = re.compile(r"\bhttps?://[^\s\"'<>`|]{1,2048}", re.IGNORECASE)
EMAIL_TOKEN = re.compile(r"[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,10}[A-Za-z]{2,63}")
STIX_TERM = re.compile(
    r"^\s*\[\s*([a-z0-9-]+):([a-z_]+(?:\.'[A-Za-z0-9-]+')?)\s*=\s*'((?:[^'\\]|\\.){1,2048})'\s*\]\s*$"
)
STIX_PATHS = {
    ("ipv4-addr", "value"): "ip",
    ("ipv6-addr", "value"): "ip",
    ("domain-name", "value"): "domain",
    ("url", "value"): "url",
    ("email-addr", "value"): "email",
    ("file", "name"): "filename",
    ("file", "hashes.'SHA-256'"): "sha256",
    ("file", "hashes.'SHA-1'"): "sha1",
    ("file", "hashes.'MD5'"): "md5",
}


class IocError(ValueError):
    pass


def refang(value: str) -> str:
    out = value.strip()
    out = re.sub(r"(?i)\bhxxp(s?)", r"http\1", out)
    out = re.sub(r"(?i)\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*\.\s*\}", ".", out)
    out = re.sub(r"(?i)\[\s*(?:@|at)\s*\]|\(\s*(?:@|at)\s*\)", "@", out)
    out = out.replace("[://]", "://").replace("[:]", ":")
    return out


def normalize(ioc_type: str, value: str) -> str:
    """Canonical form of an indicator; raises :class:`IocError` when it is not valid."""
    if ioc_type not in IOC_TYPES:
        raise IocError(f"unknown IOC type {ioc_type!r} (use one of {', '.join(IOC_TYPES)})")
    if not isinstance(value, str) or not value.strip():
        raise IocError("IOC value must be a non-empty string")
    if len(value) > MAX_VALUE:
        raise IocError(f"IOC value longer than {MAX_VALUE} characters")
    text = refang(value)
    if ioc_type == "ip":
        try:
            addr = ipaddress.ip_address(text.strip("[]"))
        except ValueError as exc:
            raise IocError(f"{value!r} is not an IP address") from exc
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        return str(addr)
    if ioc_type in HASH_LEN:
        text = text.lower().removeprefix(f"{ioc_type}:")
        if len(text) != HASH_LEN[ioc_type] or not HEX.fullmatch(text):
            raise IocError(f"{value!r} is not a {ioc_type} hash")
        return text
    if ioc_type == "domain":
        text = text.lower().rstrip(".")
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise IocError(f"{value!r} is not a domain name") from exc
        if not DOMAIN.fullmatch(text):
            raise IocError(f"{value!r} is not a domain name")
        return text
    if ioc_type == "email":
        text = text.lower()
        if not EMAIL.fullmatch(text):
            raise IocError(f"{value!r} is not an e-mail address")
        return text
    if ioc_type == "url":
        return normalize_url(text, value)
    name = re.split(r"[\\/]", text)[-1].casefold()
    if not name or name in (".", ".."):
        raise IocError(f"{value!r} is not a file name")
    return name


def normalize_url(text: str, original: str | None = None) -> str:
    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise IocError(f"{original or text!r} is not a URL") from exc
    if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.netloc:
        raise IocError(f"{original or text!r} is not an http(s)/ftp URL")
    netloc = parts.netloc.lower()
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


@dataclass(frozen=True)
class IocEntry:
    id: str
    type: str
    value: str
    confidence: float = 0.5
    tlp: str | None = None
    source: str | None = None


@dataclass(frozen=True)
class IocHit:
    ioc: IocEntry
    field: str
    observed: str


class IocIndex:
    """Normalized IOC values indexed by type for O(1) lookups per extracted token."""

    def __init__(self, entries: Iterable[IocEntry]) -> None:
        self.by_type: dict[str, dict[str, IocEntry]] = {t: {} for t in IOC_TYPES}
        for entry in entries:
            self.by_type[entry.type].setdefault(entry.value, entry)
        self.size = sum(len(v) for v in self.by_type.values())

    def __len__(self) -> int:
        return self.size

    def match(self, event: Mapping[str, Any]) -> list[IocHit]:
        if not self.size:
            return []
        hits: dict[tuple[str, str], IocHit] = {}

        def add(ioc_type: str, value: str, field: str) -> None:
            entry = self.by_type[ioc_type].get(value)
            if entry is not None:
                hits.setdefault((entry.type, entry.value), IocHit(entry, field, value))

        ips = self.by_type["ip"]
        if ips:
            for name in ("src_ip", "dst_ip"):
                raw = event.get(name)
                if raw is not None:
                    try:
                        addr = ipaddress.ip_address(str(raw))
                    except ValueError:
                        continue
                    add("ip", str(addr), name)
        file_hash = event.get("file_hash")
        if isinstance(file_hash, str) and file_hash:
            algo, _, digest = file_hash.lower().rpartition(":")
            for hash_type in HASH_LEN:
                if (not algo or algo == hash_type) and len(digest) == HASH_LEN[hash_type]:
                    add(hash_type, digest, "file_hash")
        if self.by_type["filename"]:
            for name in ("file_path", "process_name"):
                value = event.get(name)
                if isinstance(value, str) and value:
                    add("filename", re.split(r"[\\/]", value)[-1].casefold(), name)
        texts: list[tuple[str, str]] = [
            (name, value)
            for name in ("cmdline", "message")
            if isinstance(value := event.get(name), str)
        ]
        if self.by_type["url"] or self.by_type["domain"]:
            for name, text in texts:
                for m in URL_TOKEN.finditer(text):
                    token = m.group(0).rstrip(".,;)]}")
                    with contextlib.suppress(IocError):
                        add("url", normalize_url(token), name)
                if self.by_type["domain"]:
                    for m in HOST_TOKEN.finditer(text):
                        labels = m.group(0).lower().split(".")
                        for i in range(len(labels) - 1):  # the domain and every parent domain
                            add("domain", ".".join(labels[i:]), name)
        if self.by_type["email"]:
            candidates = list(texts)
            if isinstance(user := event.get("user"), str):
                candidates.append(("user", user))
            for name, text in candidates:
                for m in EMAIL_TOKEN.finditer(text):
                    add("email", m.group(0).lower(), name)
        return list(hits.values())


# --------------------------------------------------------------------------- imports


@dataclass
class ParsedIoc:
    type: str
    value: str
    value_original: str
    source: str | None = None
    confidence: float | None = None
    tlp: str | None = None
    expires_at: datetime | None = None


@dataclass
class ImportResult:
    items: list[ParsedIoc]
    errors: list[dict[str, Any]]


def parse_item(index: int, raw: Mapping[str, Any], result: ImportResult) -> None:
    try:
        ioc_type = str(raw.get("type") or "").strip().lower()
        value = raw.get("value")
        if not isinstance(value, str):
            raise IocError("value is required")
        normalized = normalize(ioc_type, value)
        confidence = raw.get("confidence")
        if confidence not in (None, ""):
            confidence = float(confidence)
            if not 0.0 <= confidence <= 1.0:
                raise IocError("confidence must be between 0 and 1")
        else:
            confidence = None
        tlp = raw.get("tlp")
        tlp = str(tlp).strip().lower() if tlp not in (None, "") else None
        if tlp is not None and tlp not in TLP:
            raise IocError(f"tlp must be one of {', '.join(TLP)}")
        expires = raw.get("expires_at")
        expires_at = None
        if expires not in (None, ""):
            expires_at = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            if expires_at.tzinfo is None:
                raise IocError("expires_at needs a timezone")
            expires_at = expires_at.astimezone(UTC)
        source = raw.get("source")
        result.items.append(
            ParsedIoc(
                ioc_type,
                normalized,
                value[:MAX_VALUE],
                str(source)[:256] if source not in (None, "") else None,
                confidence,
                tlp,
                expires_at,
            )
        )
    except (IocError, ValueError, TypeError) as exc:
        result.errors.append({"index": index, "error": str(exc)[:300]})


def _check_size(text: str) -> None:
    if len(text.encode("utf-8", errors="replace")) > MAX_IMPORT_BYTES:
        raise IocError(f"import larger than {MAX_IMPORT_BYTES} bytes")


def parse_csv(text: str) -> ImportResult:
    """Header row with ``type,value`` and optional ``source,confidence,tlp,expires_at``."""
    _check_size(text)
    result = ImportResult([], [])
    reader = csv.DictReader(io.StringIO(text))
    header = {h.strip().lower() for h in (reader.fieldnames or [])}
    if not {"type", "value"} <= header:
        raise IocError("CSV needs a header row with at least 'type' and 'value'")
    unknown = header - {"type", "value", "source", "confidence", "tlp", "expires_at"}
    if unknown:
        raise IocError(f"unknown CSV columns: {sorted(unknown)}")
    for index, row in enumerate(reader):
        if index >= MAX_IMPORT_ITEMS:
            raise IocError(f"more than {MAX_IMPORT_ITEMS} rows")
        parse_item(index, {k.strip().lower(): v for k, v in row.items() if k is not None}, result)
    return result


def parse_json(text: str) -> ImportResult:
    """A JSON list of ``{type, value, source?, confidence?, tlp?, expires_at?}`` objects."""
    _check_size(text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IocError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(data, list):
        raise IocError("JSON import must be a list of objects")
    if len(data) > MAX_IMPORT_ITEMS:
        raise IocError(f"more than {MAX_IMPORT_ITEMS} items")
    result = ImportResult([], [])
    allowed = {"type", "value", "source", "confidence", "tlp", "expires_at"}
    for index, raw in enumerate(data):
        if not isinstance(raw, dict):
            result.errors.append({"index": index, "error": "not an object"})
        elif set(raw) - allowed:
            result.errors.append(
                {"index": index, "error": f"unknown keys {sorted(set(raw) - allowed)}"}
            )
        else:
            parse_item(index, raw, result)
    return result


def parse_stix(text: str) -> ImportResult:
    """STIX 2.1 bundle: ``indicator`` objects with ``pattern_type: stix`` whose pattern is one
    comparison, or several joined by ``OR``, on the paths in ``STIX_PATHS``. Anything else (AND,
    other objects/paths, observation operators) is reported per indicator, never guessed."""
    _check_size(text)
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IocError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise IocError("STIX import must be a bundle object")
    objects = bundle.get("objects") or []
    if not isinstance(objects, list) or len(objects) > MAX_IMPORT_ITEMS:
        raise IocError(f"bundle must hold at most {MAX_IMPORT_ITEMS} objects")
    result = ImportResult([], [])
    for index, obj in enumerate(objects):
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        if obj.get("pattern_type", "stix") != "stix":
            result.errors.append({"index": index, "error": "only pattern_type 'stix' supported"})
            continue
        pattern = obj.get("pattern")
        if not isinstance(pattern, str) or len(pattern) > 8192:
            result.errors.append({"index": index, "error": "missing or oversized pattern"})
            continue
        confidence = obj.get("confidence")
        conf = float(confidence) / 100 if isinstance(confidence, int | float) else None
        for term in re.split(r"\s+OR\s+", pattern.strip()):
            m = STIX_TERM.fullmatch(term)
            kind = STIX_PATHS.get((m.group(1), m.group(2))) if m else None
            if m is None or kind is None:
                result.errors.append(
                    {"index": index, "error": f"unsupported STIX pattern term {term[:120]!r}"}
                )
                continue
            value = m.group(3).replace("\\'", "'").replace("\\\\", "\\")
            parse_item(
                index,
                {
                    "type": kind,
                    "value": value,
                    "source": obj.get("name") or obj.get("id"),
                    "confidence": conf,
                    "expires_at": obj.get("valid_until"),
                },
                result,
            )
    return result

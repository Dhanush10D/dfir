"""Deterministic, bounded decoding and indicator extraction for scripts and command lines (A7,
guide 13.9). Pure Python; nothing is ever executed or written.

Layers peeled (breadth-first, at most ``MAX_DEPTH`` deep and ``MAX_LAYERS`` in total):
PowerShell ``-EncodedCommand`` (base64 of UTF-16LE), ``FromBase64String('...')`` (with gzip or
raw deflate streams), long standalone base64 blobs, char-code arrays (``[char]72``,
``String.fromCharCode(72, ...)``, ``chr(72)``), ``\\xNN`` escapes and long hex runs, and URL
escapes. Every decoded layer is capped at ``MAX_LAYER_BYTES``; decompression is streamed with a
size cap and a ratio cap (bombs stop early).

Indicators: URLs, domains (TLD allowlist), IPv4, e-mail addresses, MD5/SHA-1/SHA-256, Windows
paths, registry keys; defanged forms (``hxxp``, ``[.]``) are normalized. ATT&CK hints come from a
reviewed keyword table (``HINTS``); they are candidates for the analyst, not verdicts.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import ipaddress
import re
import urllib.parse
import zlib
from dataclasses import asdict, dataclass, field
from typing import Any

MAX_INPUT_CHARS = 200_000
MAX_LAYER_BYTES = 1024 * 1024
MAX_RATIO = 100
MAX_DEPTH = 4
MAX_LAYERS = 12
MAX_INDICATORS = 500
MAX_CHAR_CODES = 100_000

# PowerShell accepts any prefix of -EncodedCommand (-e, -en, -enc, ...) and -ec.
_ENC_SWITCH = "(?:ec|" + "|".join("encodedcommand"[:n] for n in range(1, 15)) + ")"
ENCODED_CMD_RE = re.compile(rf"(?i)(?:^|\s)[-/]{_ENC_SWITCH}\s+['\"]?([A-Za-z0-9+/]{{8,}}={{0,2}})")
FROM_B64_RE = re.compile(r"(?i)FromBase64String\(\s*['\"]([A-Za-z0-9+/\s]{8,}={0,2})['\"]\s*\)")
B64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")
PS_CHAR_RE = re.compile(r"(?i)\[char\]\s*\(?\s*(0x[0-9a-f]{1,6}|\d{1,7})\s*\)?")
CHAR_ARRAY_RE = re.compile(
    r"(?i)\[char\[\]\]\s*\(\s*((?:(?:0x[0-9a-f]{1,6}|\d{1,7})\s*,\s*){2,}(?:0x[0-9a-f]{1,6}|\d{1,7}))\s*\)"
)
FROMCHARCODE_RE = re.compile(r"(?i)fromCharCode\(\s*((?:\d{1,7}\s*,\s*)+\d{1,7})\s*\)")
CHR_RE = re.compile(r"(?i)\bchrw?\(\s*(\d{1,7})\s*\)")
HEX_ESCAPE_RE = re.compile(r"((?:\\x[0-9a-fA-F]{2}){4,})")
HEX_RUN_RE = re.compile(r"(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}){24,})(?![0-9a-fA-F])")
URL_ESCAPE_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")

TLDS = (
    "com|net|org|io|ru|cn|info|biz|xyz|top|co|uk|de|fr|nl|onion|me|cc|tk|su|in|us|app|dev|site"
    "|online|club|pw|ws|link|live|shop|store|tech|cloud|zip|mov|ly|to|gg|su|kz|ir|kp|br|jp|au"
)
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s'\"<>()\[\]{}|\\^`]{3,2000}")
DOMAIN_RE = re.compile(
    # not after @ (e-mail), / \ : (paths, URLs) or inside a longer dotted name
    rf"(?i)(?<![\w.@\-\\/:$%])((?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{TLDS}))"
    r"(?![\w-]|\.\w)"
)
NOT_DOMAINS = frozenset({"system.net", "microsoft.net", "asp.net"})
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")
HASH_RE = re.compile(
    r"(?<![0-9a-fA-F])([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])"
)
WIN_PATH_RE = re.compile(
    r"(?i)(?<![\w])(?:[a-z]:\\|%[a-z_]{2,30}%\\|\\\\[\w.$-]+\\)[^\s\"'|;<>*?]{1,400}"
)
REG_RE = re.compile(
    r"(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS"
    r"|CURRENT_CONFIG))(?::)?\\[^\s\"';|]{1,400}"
)

# (pattern, technique, reason) - reviewed static hints, matched on the lower-cased layer text.
HINTS: tuple[tuple[re.Pattern[str], str, str], ...] = tuple(
    (re.compile(p), t, r)
    for p, t, r in (
        (
            r"\b(iex|invoke-expression)\b",
            "T1059.001",
            "PowerShell Invoke-Expression runs a string as code",
        ),
        (
            r"powershell(\.exe)?\b.*\s[-/]e(nc|ncodedcommand|c)?\s",
            "T1027",
            "PowerShell encoded command hides the script text",
        ),
        (r"\bpowershell(\.exe)?\b|\bpwsh\b", "T1059.001", "PowerShell interpreter"),
        (
            r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|start-bitstransfer|net\.webclient|\bcurl(\.exe)?\s+-|\bwget\s",
            "T1105",
            "downloads content from the network",
        ),
        (r"[-/]w(indowstyle)?\s+(hidden|1)\b", "T1564.003", "hidden window"),
        (
            r"frombase64string|\[convert\]::|base64\s+(-d|--decode)|certutil.*-decode",
            "T1140",
            "decodes an obfuscated payload",
        ),
        (r"certutil(\.exe)?.*-urlcache", "T1105", "certutil used as a downloader"),
        (
            r"schtasks(\.exe)?\s+/create|register-scheduledtask",
            "T1053.005",
            "creates a scheduled task",
        ),
        (r"\\currentversion\\run(once)?\b", "T1547.001", "Run/RunOnce registry key persistence"),
        (
            r"vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|wbadmin.*delete",
            "T1490",
            "deletes shadow copies or backups",
        ),
        (r"wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog", "T1070.001", "clears event logs"),
        (
            r"mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs(\.dll)?.*minidump",
            "T1003.001",
            "LSASS credential dumping",
        ),
        (r"\brundll32(\.exe)?\b", "T1218.011", "rundll32 proxy execution"),
        (r"\bregsvr32(\.exe)?\b", "T1218.010", "regsvr32 proxy execution"),
        (r"\bmshta(\.exe)?\b", "T1218.005", "mshta proxy execution"),
        (r"\bnet1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add", "T1136.001", "creates a local account"),
        (r"/dev/tcp/|\bnc(at)?\s+(-\w+\s+)*-e\s|bash\s+-i\s+>&", "T1059.004", "reverse shell"),
        (r"\bcrontab\b|/etc/cron", "T1053.003", "cron persistence"),
        (
            r"set-mppreference.*-disable|add-mppreference.*-exclusion|amsiutils|amsiinitfailed",
            "T1562.001",
            "disables or evades security tools",
        ),
        (r"\bbitsadmin(\.exe)?\s+/transfer", "T1197", "BITS job transfer"),
        (r"\bwmic(\.exe)?\b.*process\s+call\s+create", "T1047", "WMI process creation"),
        (r"\bcmd(\.exe)?\s+/c\b", "T1059.003", "Windows command shell"),
    )
)


@dataclass(frozen=True)
class Layer:
    index: int
    parent: int | None
    method: str
    text: str
    truncated: bool = False


@dataclass(frozen=True)
class IndicatorHit:
    type: str
    value: str
    layer: int


@dataclass
class ScriptAnalysis:
    layers: list[Layer] = field(default_factory=list)
    indicators: list[IndicatorHit] = field(default_factory=list)
    techniques: list[dict[str, str]] = field(default_factory=list)
    truncated: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "layers": [asdict(x) for x in self.layers],
            "indicators": [asdict(x) for x in self.indicators],
            "techniques": list(self.techniques),
            "truncated": self.truncated,
            "notes": list(self.notes),
        }


# ------------------------------------------------------------------------------ decoders


def _b64(data: str) -> bytes | None:
    data = re.sub(r"\s+", "", data)
    if len(data) > MAX_LAYER_BYTES * 2:
        return None
    try:
        return base64.b64decode(data + "=" * (-len(data) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _inflate(raw: bytes) -> tuple[bytes | None, str]:
    """gzip or raw/zlib deflate with an output cap and a ratio cap."""
    for wbits, name in ((31, "gzip"), (-15, "deflate"), (15, "zlib")):
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(raw, MAX_LAYER_BYTES + 1)
        except zlib.error:
            continue
        if not out:
            continue
        if len(out) > MAX_LAYER_BYTES or len(out) > max(len(raw), 1024) * MAX_RATIO:
            return None, f"{name}: decompression limit reached (bomb guard)"
        return out, name
    return None, ""


def _text(raw: bytes) -> str | None:
    """Printable text from bytes (UTF-16LE when it looks like it, else UTF-8/Latin-1)."""
    if not raw:
        return None
    candidates: list[str] = []
    if len(raw) >= 4 and raw[1::2].count(0) > len(raw) // 4:
        with contextlib.suppress(UnicodeDecodeError):
            candidates.append(raw.decode("utf-16-le"))
    for enc in ("utf-8", "latin-1"):
        try:
            candidates.append(raw.decode(enc))
            break
        except UnicodeDecodeError:
            continue
    for text in candidates:
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if printable / max(len(text), 1) >= 0.9:
            return text
    return None


def _codes(numbers: list[str]) -> str | None:
    if len(numbers) > MAX_CHAR_CODES:
        return None
    out = []
    for n in numbers:
        v = int(n, 16) if n.lower().startswith("0x") else int(n)
        if v > 0x10FFFF:
            return None
        out.append(chr(v))
    return "".join(out)


def _candidates(text: str) -> list[tuple[str, str]]:
    """(method, decoded text) pairs found directly in ``text``."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(method: str, value: str | None) -> None:
        if value and value.strip() and value not in seen and value != text:
            seen.add(value)
            found.append((method, value[:MAX_LAYER_BYTES]))

    for m in ENCODED_CMD_RE.finditer(text):
        raw = _b64(m.group(1))
        if raw is not None:
            try:
                add("powershell_encodedcommand", raw.decode("utf-16-le"))
            except UnicodeDecodeError:
                add("powershell_encodedcommand", _text(raw))
    for m in FROM_B64_RE.finditer(text):
        raw = _b64(m.group(1))
        if raw is None:
            continue
        inflated, method = _inflate(raw)
        if inflated is not None:
            add(f"frombase64string+{method}", _text(inflated))
        else:
            add("frombase64string", _text(raw))
    for m in B64_BLOB_RE.finditer(text):
        raw = _b64(m.group(1))
        if raw is None:
            continue
        if raw[:2] == b"\x1f\x8b":
            inflated, method = _inflate(raw)
            add(f"base64+{method}", _text(inflated) if inflated else None)
        else:
            add("base64", _text(raw))
    arr = CHAR_ARRAY_RE.findall(text)
    for group in arr:
        add("char_array", _codes(re.findall(r"0x[0-9a-fA-F]+|\d+", group)))
    ps_chars = PS_CHAR_RE.findall(text)
    if len(ps_chars) >= 3:
        add("powershell_char", _codes(ps_chars))
    for group in FROMCHARCODE_RE.findall(text):
        add("fromcharcode", _codes(re.findall(r"\d+", group)))
    chrs = CHR_RE.findall(text)
    if len(chrs) >= 3:
        add("chr", _codes(chrs))
    for m in HEX_ESCAPE_RE.finditer(text):
        add("hex_escape", _text(bytes.fromhex(m.group(1).replace("\\x", ""))))
    for m in HEX_RUN_RE.finditer(text):
        run = m.group(1)
        if len(run) in (32, 40, 64):
            continue  # a hash, not data
        add("hex", _text(bytes.fromhex(run)))
    if URL_ESCAPE_RE.search(text):
        add("url_escape", urllib.parse.unquote(text))
    return found


# ------------------------------------------------------------------------------ indicators


def defang(text: str) -> str:
    text = re.sub(r"(?i)hxxp", "http", text)
    text = re.sub(r"(?i)fxp", "ftp", text)
    return (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[:]", ":")
        .replace("[@]", "@")
        .replace("[at]", "@")
    )


def _indicators(text: str, layer: int) -> list[IndicatorHit]:
    t = defang(text)
    hits: list[IndicatorHit] = []
    urls = [u.rstrip(".,;)'\"") for u in URL_RE.findall(t)]
    hits += [IndicatorHit("url", u, layer) for u in urls]
    url_hosts = {urllib.parse.urlsplit(u).hostname or "" for u in urls}
    for ip in IPV4_RE.findall(t):
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        hits.append(IndicatorHit("ip", ip, layer))
    emails = EMAIL_RE.findall(t)
    hits += [IndicatorHit("email", e, layer) for e in emails]
    email_domains = {e.split("@", 1)[1].lower() for e in emails}
    for d in DOMAIN_RE.findall(t):
        dl = d.lower()
        if dl in NOT_DOMAINS or dl in url_hosts or dl in email_domains:
            continue
        hits.append(IndicatorHit("domain", dl, layer))
    hits += [IndicatorHit("hash", h.lower(), layer) for h in HASH_RE.findall(t)]
    hits += [IndicatorHit("path", p.rstrip(".,;)'\""), layer) for p in WIN_PATH_RE.findall(t)]
    hits += [IndicatorHit("registry", r.rstrip(".,;)'\""), layer) for r in REG_RE.findall(t)]
    return hits


def analyze(text: str) -> ScriptAnalysis:
    """Decode ``text`` layer by layer and extract indicators and ATT&CK hints."""
    result = ScriptAnalysis()
    if len(text) > MAX_INPUT_CHARS:
        text = text[:MAX_INPUT_CHARS]
        result.truncated = True
        result.notes.append(f"input truncated to {MAX_INPUT_CHARS} characters")
    result.layers.append(Layer(0, None, "original", text))
    queue: list[tuple[int, int]] = [(0, 0)]  # (layer index, depth)
    seen = {text}
    while queue:
        idx, depth = queue.pop(0)
        if depth >= MAX_DEPTH:
            continue
        for method, decoded in _candidates(result.layers[idx].text):
            if decoded in seen:
                continue
            if len(result.layers) >= MAX_LAYERS:
                result.truncated = True
                result.notes.append(f"stopped after {MAX_LAYERS} layers")
                queue.clear()
                break
            seen.add(decoded)
            layer = Layer(len(result.layers), idx, method, decoded, len(decoded) >= MAX_LAYER_BYTES)
            result.layers.append(layer)
            queue.append((layer.index, depth + 1))

    uniq: dict[tuple[str, str], IndicatorHit] = {}
    for layer in result.layers:
        for hit in _indicators(layer.text, layer.index):
            key = (hit.type, hit.value.lower())
            if key not in uniq and len(uniq) < MAX_INDICATORS:
                uniq[key] = hit
    result.indicators = list(uniq.values())

    techniques: dict[str, str] = {}
    for layer in result.layers:
        low = layer.text.lower()
        for pattern, technique, reason in HINTS:
            if technique not in techniques and pattern.search(low):
                techniques[technique] = reason
    result.techniques = [{"technique": t, "reason": r} for t, r in sorted(techniques.items())]
    return result

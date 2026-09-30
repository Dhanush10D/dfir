"""Evidence text hygiene for prompts (guide 13.6 items 1, 5 and 6).

``clean_text`` makes an untrusted value safe to place inside an ``<evidence>`` data block:

* Unicode NFKC; control characters, zero-width, bidi and other format characters removed;
* line breaks shown as the two characters ``\\n`` (a record is always exactly one line, so evidence
  can never start a new record line or a new block);
* ``<`` and ``>`` replaced by fullwidth look-alikes, so no tag (``</evidence>``, ``<system>``)
  can be opened or closed from inside the data;
* record-id look-alikes such as ``[E12]`` rewritten to ``(E12)`` (no forged record ids);
* truncated to a per-field cap with a visible marker.

``detect_injection`` flags instruction-like text (the flags are shown to the analyst and stored
with the interaction; they are also a detection signal in their own right).
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

# Record-id look-alikes: [E12], [ A3 ], [S1] ...
FAKE_ID_RE = re.compile(r"\[\s*([EASD])\s*(\d{1,6})\s*\]", re.IGNORECASE)
LINE_BREAKS = re.compile(r"\r\n|\r|\n|\u0085|\u2028|\u2029")
B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
FW_LT = "\N{FULLWIDTH LESS-THAN SIGN}"
FW_GT = "\N{FULLWIDTH GREATER-THAN SIGN}"
TRUNCATION_MARK = "…[truncated {n} chars]"
MAX_SCAN = 200_000  # characters examined by detect_injection per value


def _drop_char(ch: str) -> bool:
    cat = unicodedata.category(ch)
    # Cc = control, Cf = format (zero-width, bidi overrides, soft hyphen), Co/Cs/Cn = unusual.
    return cat in ("Cc", "Cf", "Co", "Cs", "Cn")


def strip_invisible(text: str) -> str:
    """NFKC and remove control/format characters (tabs become spaces, line breaks kept)."""
    text = unicodedata.normalize("NFKC", text).replace("\t", " ")
    text = LINE_BREAKS.sub("\n", text)
    return "".join(ch for ch in text if ch == "\n" or not _drop_char(ch))


def has_hidden_characters(text: str) -> bool:
    return any(
        unicodedata.category(ch) == "Cf"
        or (unicodedata.category(ch) == "Cc" and ch not in "\t\r\n")
        for ch in text
    )


def clean_text(value: object, max_chars: int) -> str:
    """Sanitize one untrusted value for a data block (see module docstring)."""
    if value is None:
        return ""
    text = strip_invisible(str(value))
    text = text.replace("\n", "\\n")
    text = text.replace("<", FW_LT).replace(">", FW_GT)
    text = FAKE_ID_RE.sub(lambda m: f"({m.group(1).upper()}{m.group(2)})", text)
    text = re.sub(r" {2,}", " ", text).strip()
    if len(text) > max_chars:
        cut = len(text) - max_chars
        text = text[:max_chars] + TRUNCATION_MARK.format(n=cut)
    return text


# --------------------------------------------------------------------------- injection heuristics

PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_instructions": re.compile(
        r"\b(ignore|disregard|forget|override|bypass|skip)\b.{0,40}?"
        r"\b(previous|prior|above|earlier|all|any|the|your|system|these|those)\b.{0,40}?"
        r"\b(instructions?|rules?|prompts?|directives?|guidelines?|guardrails?|constraints?)\b"
    ),
    "role_change": re.compile(
        r"\byou (are|must|will|should) now\b|\bact as\b|\bfrom now on\b|\bpretend (to be|you)\b"
        r"|\byour (new |real )?(task|role|job|purpose|instructions?) (is|are)\b"
        r"|\b(new|updated|additional|real|hidden|secret) (instructions?|task|rules?|orders?)\b"
    ),
    "role_marker": re.compile(
        r"(^|\n|\\n)\s*(system|assistant|developer)\s*:"
        r"|[<\uff1c]\s*/?\s*(system|assistant|user|developer|instructions?|im_start|im_end)\b"
        r"|\[/?(inst|system)\]|#{2,}\s*(system|instruction)"
    ),
    "delimiter": re.compile(r"[<\uff1c]\s*/?\s*(evidence|question|context|data|untrusted)\b"),
    "verdict_steering": re.compile(
        r"\b(mark|classify|label|report|treat|flag|consider|rate|assess|score)\b.{0,50}?"
        r"\b(benign|clean|safe|harmless|false[ -]?positive|legitimate|not malicious|likely_benign"
        r"|no threat|low risk)\b"
        r"|\b(do not|don't|never|must not)\b.{0,25}?"
        r"\b(report|flag|mention|alert|escalate|cite|include)\b"
        r"|\bnothing (suspicious|malicious|to see)\b"
    ),
    "fake_output": re.compile(
        r"[\"'](assessment|summary|key_facts|cites|query|answer|status|risk|confidence)[\"']\s*:"
    ),
    "prompt_exfiltration": re.compile(
        r"\b(system prompt|your (instructions|prompt|rules)|reveal .{0,20}(prompt|instructions)"
        r"|print .{0,20}(prompt|instructions))\b"
    ),
}


def _normalized(text: str) -> str:
    text = strip_invisible(text[:MAX_SCAN]).lower()
    return re.sub(r"\s+", " ", text)


def _decoded_base64(text: str) -> list[str]:
    out: list[str] = []
    for token in B64_TOKEN.findall(text)[:50]:
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        for enc in ("utf-8", "utf-16-le"):
            try:
                decoded = raw.decode(enc)
            except UnicodeDecodeError:
                continue
            printable = sum(ch.isprintable() or ch.isspace() for ch in decoded)
            if decoded and printable / len(decoded) > 0.9:
                out.append(decoded)
                break
    return out


def detect_injection(text: str) -> list[str]:
    """Names of the heuristics that fire on ``text`` (empty list = nothing instruction-like)."""
    if not text:
        return []
    flags: set[str] = set()
    if has_hidden_characters(text[:MAX_SCAN]):
        flags.add("hidden_characters")
    if FAKE_ID_RE.search(text[:MAX_SCAN]):
        flags.add("fake_record_id")
    norm = _normalized(text)
    for name, pattern in PATTERNS.items():
        if pattern.search(norm):
            flags.add(name)
    for decoded in _decoded_base64(text[:MAX_SCAN]):
        inner = _normalized(decoded)
        for name, pattern in PATTERNS.items():
            if pattern.search(inner):
                flags.add(f"base64:{name}")
    return sorted(flags)

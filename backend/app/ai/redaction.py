"""Redaction before hosted model calls (guide 13.10), with a reversible server-side mapping.

Policies:

* ``none``: nothing is changed.
* ``standard``: secrets (private-key blocks, password/token/API-key assignments, bearer tokens,
  AWS access key ids, JWTs) and e-mail addresses.
* ``strict``: standard + IPv4/IPv6 addresses and the values of ``user=`` / ``host=`` fields of
  evidence records (user and host names elsewhere in free text are not recognised: regex
  redaction is best effort, documented in docs/ai.md).

Every distinct value gets a stable placeholder ``[TYPE_N]`` within one request; ``restore`` puts
the original values back into the model output for display. Hashes and technical ids are kept.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Any, Literal

Policy = Literal["none", "standard", "strict"]

# Apply these to RAW values (before sanitizing, quoting and truncation: see packs.py), otherwise
# escaping can split a secret from its key and truncation can cut off the end of a block.
_CREDENTIAL_NAMES = (  # key names that precede a credential value
    r"password|passwd|passphrase|passcode|secret|token|api[_-]?key|access[_-]?key"
    r"|secret[_-]?access[_-]?key|client[_-]?secret|private[_-]?key"
)
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    # (placeholder type, pattern, group holding the secret value; 0 = whole match)
    (
        # A complete block, or an unterminated one (cut or partial) up to the end of the value.
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?-----"
            r"(?:.{0,20000}?-----END [A-Z0-9 ]{0,40}PRIVATE KEY( BLOCK)?-----|.{0,20000})",
            re.DOTALL,
        ),
        0,
    ),
    # JWT/JWS: header and payload are base64url JSON ("eyJ"); the signature may be any length
    # (or missing if the value was cut).
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?"), 0),
    ("AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("TOKEN", re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{12,})"), 1),
    # user:password@host in URLs
    ("SECRET", re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,20}://[^/\s:@]{1,100}:([^/\s@]{1,200})@"), 1),
    (
        # key=value, key: value, "key": "value", --key value-less forms are not recognised.
        "SECRET",
        re.compile(
            rf"(?i)\b[\w-]{{0,40}}?(?:{_CREDENTIAL_NAMES})\b[\"']?\s*[=:]\s*"
            r"(\"[^\"\n]{1,200}\"|'[^'\n]{1,200}'|[^\s\"',;&|]{1,200})"
        ),
        1,
    ),
]
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b")
IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"
)
# Candidates only; ipaddress decides (so "08:12:03" in a timestamp or a MAC is never an IPv6).
IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f:]{2,39}(?![0-9A-Fa-f:])")
FIELD_RE = re.compile(r"\b(user|host)=(\"(?:[^\"\\]|\\.)*\"|[^\s]+)")
PLACEHOLDER_RE = re.compile(r"\[(?:PRIVATE_KEY|JWT|AWS_KEY|TOKEN|SECRET|EMAIL|IP|USER|HOST)_\d+\]")


class Redactor:
    """One instance per request: the same value always maps to the same placeholder."""

    def __init__(self, policy: Policy) -> None:
        self.policy: Policy = policy
        self.mapping: dict[str, str] = {}  # placeholder -> original
        self._reverse: dict[tuple[str, str], str] = {}
        self.counts: dict[str, int] = {}

    def _placeholder(self, kind: str, value: str) -> str:
        key = (kind, value)
        found = self._reverse.get(key)
        if found is not None:
            return found
        n = self.counts.get(kind, 0) + 1
        self.counts[kind] = n
        ph = f"[{kind}_{n}]"
        self._reverse[key] = ph
        self.mapping[ph] = value
        return ph

    def _sub_group(self, kind: str, pattern: re.Pattern[str], group: int) -> Callable[[str], str]:
        def apply(text: str) -> str:
            def repl(m: re.Match[str]) -> str:
                if group == 0:
                    return self._placeholder(kind, m.group(0))
                value = m.group(group)
                if PLACEHOLDER_RE.fullmatch(value.strip("\"'")):
                    return m.group(0)  # already redacted (redact() is idempotent)
                start, end = m.span(group)
                s0 = m.start(0)
                whole = m.group(0)
                return whole[: start - s0] + self._placeholder(kind, value) + whole[end - s0 :]

            return pattern.sub(repl, text)

        return apply

    def redact(self, text: str) -> str:
        if self.policy == "none" or not text:
            return text
        for kind, pattern, group in _SECRET_PATTERNS:
            text = self._sub_group(kind, pattern, group)(text)
        text = EMAIL_RE.sub(lambda m: self._placeholder("EMAIL", m.group(0)), text)
        if self.policy == "strict":

            def field(m: re.Match[str]) -> str:
                if PLACEHOLDER_RE.fullmatch(m.group(2)):
                    return m.group(0)
                kind = "USER" if m.group(1) == "user" else "HOST"
                return f"{m.group(1)}={self._placeholder(kind, m.group(2))}"

            text = FIELD_RE.sub(field, text)
            text = IPV4_RE.sub(lambda m: self._placeholder("IP", m.group(0)), text)
            text = IPV6_CANDIDATE_RE.sub(self._ipv6, text)
        return text

    def redact_value(self, value: str, field: str | None = None) -> str:
        """Redact one RAW evidence value (before sanitizing/quoting/truncation).

        ``strict`` replaces whole ``user``/``host`` values; every policy other than ``none``
        then applies the secret and e-mail patterns to the value.
        """
        if self.policy == "none" or not value:
            return value
        if self.policy == "strict" and field in ("user", "host"):
            if PLACEHOLDER_RE.fullmatch(value):
                return value
            return self._placeholder("USER" if field == "user" else "HOST", value)
        return self.redact(value)

    def _ipv6(self, m: re.Match[str]) -> str:
        value = m.group(0)
        if value.count(":") < 2:
            return value
        try:
            ipaddress.IPv6Address(value)
        except ValueError:
            return value
        return self._placeholder("IP", value)

    def restore(self, obj: Any) -> Any:
        """Put original values back into (nested) model output for display."""
        if not self.mapping:
            return obj
        if isinstance(obj, str):
            return PLACEHOLDER_RE.sub(lambda m: self.mapping.get(m.group(0), m.group(0)), obj)
        if isinstance(obj, list):
            return [self.restore(v) for v in obj]
        if isinstance(obj, dict):
            return {k: self.restore(v) for k, v in obj.items()}
        return obj

    def summary(self) -> dict[str, Any]:
        """What goes into ``ai_interactions.redactions`` (mapping kept server-side only)."""
        return {"policy": self.policy, "counts": dict(self.counts), "mapping": dict(self.mapping)}

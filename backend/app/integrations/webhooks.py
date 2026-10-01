"""Webhook signatures (guide 15.6), used for outbound deliveries and inbound ingest.

``X-Timestamp`` is Unix time in seconds; ``X-Signature`` is ``sha256=<hex>`` of
HMAC-SHA256(secret, ``<timestamp>.`` + raw body). Receivers compare in constant time and reject
timestamps outside a window, which bounds how long a captured delivery can be replayed (the
ingest endpoint also remembers every accepted signed digest).
"""

from __future__ import annotations

import hashlib
import hmac
import re

SIGNATURE_PREFIX = "sha256="
HEADER_TIMESTAMP = "X-Timestamp"
HEADER_SIGNATURE = "X-Signature"
HEADER_EVENT = "X-Event"
HEADER_DELIVERY = "X-Delivery-Id"
TIMESTAMP_RE = re.compile(r"^[0-9]{1,12}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def digest(secret: bytes, timestamp: str, body: bytes) -> str:
    return hmac.new(secret, timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


def sign(secret: str, timestamp: int, body: bytes) -> str:
    """The ``X-Signature`` value for a body sent at ``timestamp``."""
    return SIGNATURE_PREFIX + digest(secret.encode("utf-8"), str(int(timestamp)), body)


def verify(
    secret: str,
    timestamp: str | None,
    body: bytes,
    signature: str | None,
    *,
    now: float,
    window_s: int,
) -> str | None:
    """The signed digest (hex) when the delivery is authentic and fresh, else None.

    Always computes the HMAC (also for malformed input), so the time taken does not tell a caller
    which check failed.
    """
    ts = (timestamp or "").strip()
    ts_ok = bool(TIMESTAMP_RE.fullmatch(ts))
    given = (signature or "").strip().lower()
    given = given.removeprefix(SIGNATURE_PREFIX)
    expected = digest(secret.encode("utf-8"), ts if ts_ok else "0", body)
    sig_ok = hmac.compare_digest(expected, given if HEX64_RE.fullmatch(given) else "0" * 64)
    fresh = ts_ok and abs(now - int(ts)) <= window_s
    return expected if (sig_ok and ts_ok and fresh) else None

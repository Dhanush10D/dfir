"""Indicator enrichment providers (guide 19.3): VirusTotal and MISP behind one interface, plus a
deterministic fake for tests, smokes and demos.

* Only an indicator leaves the platform: a hash, IP address, domain or URL. Never a file, never
  evidence content, never the case it belongs to.
* TLP decides where an indicator may go (:func:`tlp_allows`): a public service such as VirusTotal
  receives ``clear``/``white``/``green`` only; MISP up to the integration's ``max_tlp`` (never
  ``red``); an indicator without a TLP counts as ``amber``. Sightings follow the same rule.
* Providers talk to the network only through :class:`app.integrations.outbound.OutboundHttp`.
  Responses are untrusted: only numbers and short tokens are kept.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol
from urllib.parse import quote

from app.integrations.outbound import (
    HttpResponse,
    OutboundBlockedError,
    OutboundError,
    OutboundHttp,
)

ENRICHABLE_TYPES = ("ip", "domain", "url", "sha256", "sha1", "md5")
HASH_TYPES = ("sha256", "sha1", "md5")
TLP_LEVEL = {"clear": 0, "white": 0, "green": 1, "amber": 2, "amber+strict": 3, "red": 4}
DEFAULT_TLP = "amber"  # an indicator without a marking is treated as restricted
VIRUSTOTAL_MAX_TLP = "green"
MISP_MAX_TLP_CHOICES = ("clear", "green", "amber", "amber+strict")
VERDICTS = ("malicious", "suspicious", "harmless", "unknown")
VIRUSTOTAL_URL = "https://www.virustotal.com"
TOKEN_RE = re.compile(r"^[A-Za-z0-9 _.:/+-]{1,80}$")
MAX_TAGS = 20


def tlp_allows(max_tlp: str, tlp: str | None) -> bool:
    """May an indicator marked ``tlp`` be sent to a destination cleared up to ``max_tlp``?"""
    level = TLP_LEVEL.get((tlp or DEFAULT_TLP).lower())
    limit = TLP_LEVEL.get(max_tlp.lower())
    if level is None or limit is None or limit >= TLP_LEVEL["red"]:
        return False
    return level <= limit


class EnrichmentError(Exception):
    """A lookup failed; ``category`` is safe to store and show."""

    def __init__(self, category: str, *, transient: bool = False) -> None:
        super().__init__(category)
        self.category = category
        self.transient = transient


@dataclass(frozen=True)
class Indicator:
    type: str
    value: str


@dataclass(frozen=True)
class Verdict:
    verdict: str  # malicious | suspicious | harmless | unknown
    score: float | None = None  # 0-1 share of engines/sources that flag it, when known
    summary: dict[str, Any] = field(default_factory=dict)


class EnrichmentProvider(Protocol):
    name: str
    max_tlp: str

    def supports(self, ioc_type: str) -> bool: ...

    def lookup(self, indicator: Indicator) -> Verdict: ...

    def add_sighting(self, indicator: Indicator, when: datetime) -> None: ...


def _send(
    http: OutboundHttp, method: str, url: str, headers: Mapping[str, str], body: bytes
) -> HttpResponse:
    try:
        return http.request(method, url, headers=headers, body=body)
    except OutboundBlockedError as exc:
        raise EnrichmentError(exc.category) from exc
    except OutboundError as exc:
        raise EnrichmentError(exc.category, transient=exc.transient) from exc


def _json(resp: HttpResponse) -> dict[str, Any]:
    try:
        data = json.loads(resp.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EnrichmentError("invalid_response") from exc
    if not isinstance(data, dict):
        raise EnrichmentError("invalid_response")
    return data


def _status(resp: HttpResponse) -> None:
    if resp.status == 429:
        raise EnrichmentError("rate_limited", transient=True)
    if resp.status in (401, 403):
        raise EnrichmentError("unauthorized")
    if resp.status >= 500:
        raise EnrichmentError(f"http_{resp.status}", transient=True)
    if not resp.ok:
        raise EnrichmentError(f"http_{resp.status}")


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _tokens(values: Any) -> list[str]:
    out: list[str] = []
    if isinstance(values, list):
        for item in values:
            name = item.get("name") if isinstance(item, dict) else item
            if isinstance(name, str) and TOKEN_RE.fullmatch(name) and name not in out:
                out.append(name)
            if len(out) >= MAX_TAGS:
                break
    return out


class VirusTotalProvider:
    """VirusTotal API v3 reputation lookups (GET only; nothing is uploaded)."""

    name = "virustotal"
    max_tlp = VIRUSTOTAL_MAX_TLP

    def __init__(self, http: OutboundHttp, api_key: str, base_url: str = VIRUSTOTAL_URL) -> None:
        self.http = http
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in ENRICHABLE_TYPES

    def _path(self, indicator: Indicator) -> str:
        if indicator.type in HASH_TYPES:
            return f"/api/v3/files/{quote(indicator.value, safe='')}"
        if indicator.type == "ip":
            return f"/api/v3/ip_addresses/{quote(indicator.value, safe='')}"
        if indicator.type == "domain":
            return f"/api/v3/domains/{quote(indicator.value, safe='')}"
        if indicator.type == "url":
            url_id = base64.urlsafe_b64encode(indicator.value.encode("utf-8")).decode().rstrip("=")
            return f"/api/v3/urls/{url_id}"
        raise EnrichmentError("unsupported_type")

    def lookup(self, indicator: Indicator) -> Verdict:
        resp = _send(
            self.http,
            "GET",
            self.base_url + self._path(indicator),
            {"x-apikey": self.api_key, "Accept": "application/json"},
            b"",
        )
        if resp.status == 404:
            return Verdict("unknown", None, {"found": False})
        _status(resp)
        data = _json(resp).get("data")
        attrs = data.get("attributes") if isinstance(data, dict) else None
        stats = attrs.get("last_analysis_stats") if isinstance(attrs, dict) else None
        if not isinstance(stats, dict):
            raise EnrichmentError("invalid_response")
        malicious = _count(stats.get("malicious"))
        suspicious = _count(stats.get("suspicious"))
        harmless = _count(stats.get("harmless"))
        undetected = _count(stats.get("undetected"))
        total = malicious + suspicious + harmless + undetected
        verdict = "malicious" if malicious else "suspicious" if suspicious else "harmless"
        if total == 0:
            verdict = "unknown"
        return Verdict(
            verdict,
            round((malicious + suspicious) / total, 3) if total else None,
            {
                "found": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
            },
        )

    def add_sighting(self, indicator: Indicator, when: datetime) -> None:
        raise EnrichmentError("sightings_unsupported")


class MispProvider:
    """MISP REST: attribute search by value and sighting export."""

    name = "misp"

    def __init__(self, http: OutboundHttp, api_key: str, base_url: str, max_tlp: str) -> None:
        if max_tlp not in MISP_MAX_TLP_CHOICES:
            raise ValueError("invalid max_tlp")
        self.http = http
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.max_tlp = max_tlp

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in ENRICHABLE_TYPES

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def lookup(self, indicator: Indicator) -> Verdict:
        body = json.dumps({"returnFormat": "json", "value": indicator.value, "limit": 50})
        resp = _send(
            self.http,
            "POST",
            self.base_url + "/attributes/restSearch",
            self._headers(),
            body.encode("utf-8"),
        )
        _status(resp)
        response = _json(resp).get("response")
        attributes = response.get("Attribute") if isinstance(response, dict) else None
        if not isinstance(attributes, list):
            raise EnrichmentError("invalid_response")
        rows = [a for a in attributes[:50] if isinstance(a, dict)]
        if not rows:
            return Verdict("unknown", None, {"found": False})
        to_ids = sum(1 for a in rows if a.get("to_ids") in (True, "1", 1))
        tags: list[str] = []
        for row in rows:
            for tag in _tokens(row.get("Tag")):
                if tag not in tags and len(tags) < MAX_TAGS:
                    tags.append(tag)
        events = {str(a.get("event_id")) for a in rows if str(a.get("event_id", "")).isdigit()}
        return Verdict(
            "malicious" if to_ids else "suspicious",
            round(to_ids / len(rows), 3),
            {
                "found": True,
                "attributes": len(rows),
                "to_ids": to_ids,
                "events": len(events),
                "tags": tags,
            },
        )

    def add_sighting(self, indicator: Indicator, when: datetime) -> None:
        body = json.dumps(
            {"value": indicator.value, "timestamp": int(when.timestamp()), "source": "dfirbench"}
        )
        resp = _send(
            self.http,
            "POST",
            self.base_url + "/sightings/add",
            self._headers(),
            body.encode("utf-8"),
        )
        _status(resp)


class FakeEnrichmentProvider:
    """Deterministic offline provider (``ENRICHMENT_FAKE``): the verdict depends only on the
    indicator, nothing is sent anywhere, and every call is recorded for tests."""

    def __init__(self, name: str = "fake", max_tlp: str = "green") -> None:
        self.name = name
        self.max_tlp = max_tlp
        self.lookups: list[Indicator] = []
        self.sightings: list[Indicator] = []
        self.fail_with: EnrichmentError | None = None

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in ENRICHABLE_TYPES

    def lookup(self, indicator: Indicator) -> Verdict:
        if self.fail_with is not None:
            raise self.fail_with
        self.lookups.append(indicator)
        digest = hashlib.sha256(f"{indicator.type}:{indicator.value}".encode()).digest()
        verdict = VERDICTS[digest[0] % 3]
        flagged = digest[1] % 40 if verdict != "harmless" else 0
        return Verdict(
            verdict,
            round(flagged / 70, 3),
            {"found": True, "malicious": flagged, "harmless": 70 - flagged, "simulated": True},
        )

    def add_sighting(self, indicator: Indicator, when: datetime) -> None:
        if self.fail_with is not None:
            raise self.fail_with
        self.sightings.append(indicator)

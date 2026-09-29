"""Deterministic risk scoring (guide 11.7). Pure functions; every value is reproducible.

* ``alert_risk = severity_weight x confidence x asset_criticality`` (0-100, one decimal).
  Weights: info 5, low 20, medium 45, high 70, critical 90. There is no asset inventory yet, so
  ``asset_criticality`` is 1.0 unless a caller passes one (clamped to 0-1).
* ``host_risk = 100 x (1 - prod(1 - alert_risk_i / 100))`` over the host's scoring alerts:
  several alerts compound but never exceed 100.
* ``case_risk = min(100, max(host_risk) + 10 x min(distinct ATT&CK tactics, 3))``. The guide's
  "+0.1 per tactic" is read on the 0-1 scale (10 points on 0-100), capped at 3 tactics.
* Scoring alerts: every alert except ``false_positive`` ones and ``stale`` ones (no longer
  produced by the latest detection run). Alerts without a host are scored under ``(no host)``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from app.detection.attack import Level, tactics_for

SEVERITY_WEIGHT: dict[str, int] = {
    "info": 5,
    "low": 20,
    "medium": 45,
    "high": 70,
    "critical": 90,
}
TACTIC_POINTS = 10.0
TACTIC_CAP = 3
NO_HOST = "(no host)"


def alert_risk(severity: Level | str, confidence: float, asset_criticality: float = 1.0) -> float:
    conf = min(max(float(confidence), 0.0), 1.0)
    crit = min(max(float(asset_criticality), 0.0), 1.0)
    return round(SEVERITY_WEIGHT[str(severity)] * conf * crit, 1)


def host_risk(risks: Iterable[float]) -> float:
    remaining = 1.0
    for risk in risks:
        remaining *= 1.0 - min(max(risk, 0.0), 100.0) / 100.0
    return round(100.0 * (1.0 - remaining), 1)


def case_risk(host_risks: Iterable[float], techniques: Iterable[str]) -> float:
    top = max(host_risks, default=0.0)
    tactics = len(tactics_for(set(techniques)))
    return round(min(100.0, top + TACTIC_POINTS * min(tactics, TACTIC_CAP)), 1)


@dataclass(frozen=True)
class ScoredAlert:
    id: str
    host: str | None
    risk: float
    attack: tuple[str, ...]
    title: str


@dataclass
class RiskSummary:
    case_risk: float
    hosts: list[dict[str, object]]
    tactics: list[str]


def summarize(alerts: Iterable[ScoredAlert], top: int = 10) -> RiskSummary:
    by_host: dict[str, list[ScoredAlert]] = {}
    techniques: set[str] = set()
    for alert in alerts:
        by_host.setdefault(alert.host or NO_HOST, []).append(alert)
        techniques.update(alert.attack)
    hosts = []
    for host in sorted(by_host):
        items = sorted(by_host[host], key=lambda a: (-a.risk, a.id))
        hosts.append(
            {
                "host": host,
                "risk": host_risk(a.risk for a in items),
                "alerts": len(items),
                "contributors": [
                    {"alert_id": a.id, "title": a.title, "risk": a.risk} for a in items[:top]
                ],
            }
        )
    hosts.sort(key=lambda h: (-float(h["risk"]), str(h["host"])))  # type: ignore[arg-type]
    score = case_risk((float(h["risk"]) for h in hosts), techniques)  # type: ignore[arg-type]
    return RiskSummary(score, hosts, sorted(tactics_for(techniques)))

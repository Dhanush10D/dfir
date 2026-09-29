"""Detection, alerts, rules and IOCs (guide 15.2 "Detection, alerts, rules, IOCs").

HTTP only: authorization (case scope, 404 across cases), locking and state rules live in
``services/detection.py``, ``alerts.py``, ``rules.py`` and ``iocs.py``.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Path, Query, status

from app.api.dependencies import Alerts, CurrentPrincipal, Detections, Iocs, Meta, Rules
from app.api.v1.jobs import job_out
from app.core.permissions import Permission
from app.db.models import AlertStatus, Rule, RuleVersion, Severity
from app.schemas.detection import (
    RULE_ID_PATTERN,
    AlertDetail,
    AlertEventList,
    AlertEventOut,
    AlertHistoryOut,
    AlertList,
    AlertOut,
    AlertUpdate,
    AttackRow,
    CoverageRow,
    DetectOut,
    DetectRequest,
    IocCreate,
    IocImport,
    IocImportOut,
    IocList,
    IocOut,
    RiskOut,
    RuleCreate,
    RuleDetail,
    RuleList,
    RuleOut,
    RuleTestOut,
    RuleTestRequest,
    RuleUpdate,
    RuleVersionOut,
    SigmaImport,
    SigmaImportOut,
)
from app.schemas.events import EventOut
from app.services.alerts import UNSET, AlertFilter
from app.services.authz import require_global

router = APIRouter(tags=["detection"])
RuleId = Annotated[str, Path(pattern=RULE_ID_PATTERN, max_length=64)]


# ---------------------------------------------------------------------------------- runs


@router.post(
    "/cases/{case_id}/detect", response_model=DetectOut, status_code=status.HTTP_202_ACCEPTED
)
def run_detection(
    case_id: uuid.UUID,
    principal: CurrentPrincipal,
    detections: Detections,
    meta: Meta,
    body: DetectRequest | None = None,
) -> DetectOut:
    """Queue a detection run over the case (joins a run that is already queued)."""
    result = detections.submit(
        principal,
        case_id,
        rules=body.rules if body else None,
        trigger={"type": "manual", "user_id": str(principal.user_id)},
        meta=meta,
    )
    return DetectOut(job=job_out(result.job), created=result.created)


# ---------------------------------------------------------------------------------- alerts


@router.get("/cases/{case_id}/alerts", response_model=AlertList)
def list_alerts(
    case_id: uuid.UUID,
    principal: CurrentPrincipal,
    alerts: Alerts,
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Annotated[Severity | None, Query(description="Minimum severity")] = None,
    host: Annotated[str | None, Query(max_length=1024)] = None,
    rule_id: Annotated[str | None, Query(max_length=64)] = None,
    technique: Annotated[str | None, Query(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")] = None,
    assignee_id: uuid.UUID | None = None,
    include_stale: bool = True,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertList:
    flt = AlertFilter(status_filter, severity, host, rule_id, technique, assignee_id, include_stale)
    rows, total = alerts.list_alerts(principal, case_id, flt, limit=limit, offset=offset)
    return AlertList(
        items=[AlertOut.model_validate(a) for a in rows], total=total, limit=limit, offset=offset
    )


def _detail(alert: Any, history: list[Any]) -> AlertDetail:
    detail = AlertDetail.model_validate(alert)
    return detail.model_copy(
        update={"history": [AlertHistoryOut.model_validate(h) for h in history]}
    )


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: uuid.UUID, principal: CurrentPrincipal, alerts: Alerts) -> AlertDetail:
    alert, history = alerts.get(principal, alert_id)
    return _detail(alert, history)


@router.patch("/alerts/{alert_id}", response_model=AlertDetail)
def update_alert(
    alert_id: uuid.UUID,
    body: AlertUpdate,
    principal: CurrentPrincipal,
    alerts: Alerts,
    meta: Meta,
) -> AlertDetail:
    """Change status (with reason for TP/FP/closed) and/or assignee."""
    assignee = body.assignee_id if "assignee_id" in body.model_fields_set else UNSET
    alerts.update(
        principal,
        alert_id,
        meta,
        status=body.status,
        assignee_id=assignee,
        reason=body.reason,
        expected_status=body.expected_status,
    )
    alert, history = alerts.get(principal, alert_id)
    return _detail(alert, history)


@router.get("/alerts/{alert_id}/events", response_model=AlertEventList)
def alert_events(
    alert_id: uuid.UUID,
    principal: CurrentPrincipal,
    alerts: Alerts,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertEventList:
    links, total = alerts.events(principal, alert_id, limit=limit, offset=offset)
    return AlertEventList(
        items=[
            AlertEventOut(
                event_id=link.event_id,
                event_ts=link.event_ts,
                missing=link.event is None,
                event=EventOut.model_validate(link.event) if link.event is not None else None,
            )
            for link in links
        ],
        total=total,
    )


@router.get("/cases/{case_id}/attack", response_model=list[AttackRow])
def attack_matrix(
    case_id: uuid.UUID, principal: CurrentPrincipal, alerts: Alerts
) -> list[AttackRow]:
    return [AttackRow(**row) for row in alerts.attack_matrix(principal, case_id)]


@router.get("/cases/{case_id}/risk", response_model=RiskOut)
def case_risk(case_id: uuid.UUID, principal: CurrentPrincipal, alerts: Alerts) -> RiskOut:
    summary = alerts.risk(principal, case_id)
    return RiskOut(case_risk=summary.case_risk, tactics=summary.tactics, hosts=summary.hosts)


# ---------------------------------------------------------------------------------- rules


def _rule_detail(rule: Rule, versions: list[RuleVersion]) -> RuleDetail:
    return RuleDetail.model_validate(rule).model_copy(
        update={"versions": [RuleVersionOut.model_validate(v) for v in versions]}
    )


@router.get("/rules", response_model=RuleList)
def list_rules(
    principal: CurrentPrincipal,
    rules: Rules,
    origin: Annotated[str | None, Query(pattern="^(builtin|custom|sigma)$")] = None,
    enabled: bool | None = None,
    technique: Annotated[str | None, Query(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")] = None,
) -> RuleList:
    rules.sync_builtin()
    rows = rules.list_rules(origin=origin, enabled=enabled, technique=technique)
    return RuleList(items=[RuleOut.model_validate(r) for r in rows])


@router.get("/rules/coverage", response_model=list[CoverageRow])
def rule_coverage(principal: CurrentPrincipal, rules: Rules) -> list[CoverageRow]:
    """ATT&CK coverage of the enabled rules (generated from the rules table)."""
    rules.sync_builtin()
    return [CoverageRow.model_validate(row) for row in rules.coverage()]


@router.post("/rules/test", response_model=RuleTestOut)
def test_rule(body: RuleTestRequest, principal: CurrentPrincipal, rules: Rules) -> RuleTestOut:
    """Run a rule over sample events; nothing is stored."""
    require_global(principal, Permission.INVESTIGATE)
    events = [e.model_dump() for e in body.events]
    return RuleTestOut.model_validate(rules.test(body.yaml, events))


@router.post("/rules/import/sigma", response_model=SigmaImportOut, status_code=201)
def import_sigma(
    body: SigmaImport, principal: CurrentPrincipal, rules: Rules, meta: Meta
) -> SigmaImportOut:
    """Convert a Sigma rule (documented subset); unsupported features are a 422 with a list."""
    row, notes = rules.import_sigma(
        principal, body.yaml, meta, rule_id=body.rule_id, enabled=body.enabled
    )
    rule, versions = rules.get(row.id)
    return SigmaImportOut(rule=_rule_detail(rule, versions), notes=notes)


@router.get("/rules/{rule_id}", response_model=RuleDetail)
def get_rule(rule_id: RuleId, principal: CurrentPrincipal, rules: Rules) -> RuleDetail:
    rules.sync_builtin()
    rule, versions = rules.get(rule_id)
    return _rule_detail(rule, versions)


@router.post("/rules", response_model=RuleDetail, status_code=201)
def create_rule(
    body: RuleCreate, principal: CurrentPrincipal, rules: Rules, meta: Meta
) -> RuleDetail:
    row = rules.create(principal, body.yaml, meta, enabled=body.enabled)
    rule, versions = rules.get(row.id)
    return _rule_detail(rule, versions)


@router.patch("/rules/{rule_id}", response_model=RuleDetail)
def update_rule(
    rule_id: RuleId, body: RuleUpdate, principal: CurrentPrincipal, rules: Rules, meta: Meta
) -> RuleDetail:
    rules.update(
        principal,
        rule_id,
        meta,
        enabled=body.enabled,
        yaml_text=body.yaml,
        expected_version=body.expected_version,
    )
    rule, versions = rules.get(rule_id)
    return _rule_detail(rule, versions)


# ---------------------------------------------------------------------------------- IOCs


@router.get("/cases/{case_id}/iocs", response_model=IocList)
def list_iocs(
    case_id: uuid.UUID,
    principal: CurrentPrincipal,
    iocs: Iocs,
    ioc_type: Annotated[str | None, Query(alias="type", max_length=16)] = None,
    active: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> IocList:
    rows, total = iocs.list_iocs(
        principal, case_id, ioc_type=ioc_type, active=active, limit=limit, offset=offset
    )
    return IocList(items=[IocOut.model_validate(r) for r in rows], total=total)


@router.post("/cases/{case_id}/iocs", response_model=IocOut, status_code=201)
def create_ioc(
    case_id: uuid.UUID, body: IocCreate, principal: CurrentPrincipal, iocs: Iocs, meta: Meta
) -> IocOut:
    row, _ = iocs.create(
        principal,
        case_id,
        meta,
        ioc_type=body.type,
        value=body.value,
        source=body.source,
        confidence=body.confidence,
        tlp=body.tlp,
        expires_at=body.expires_at,
    )
    return IocOut.model_validate(row)


@router.post("/cases/{case_id}/iocs/import", response_model=IocImportOut)
def import_iocs(
    case_id: uuid.UUID, body: IocImport, principal: CurrentPrincipal, iocs: Iocs, meta: Meta
) -> IocImportOut:
    result = iocs.import_(
        principal, case_id, meta, fmt=body.format, content=body.content, default_tlp=body.tlp
    )
    return IocImportOut(**result)


@router.delete("/cases/{case_id}/iocs/{ioc_id}", response_model=IocOut)
def deactivate_ioc(
    case_id: uuid.UUID, ioc_id: uuid.UUID, principal: CurrentPrincipal, iocs: Iocs, meta: Meta
) -> IocOut:
    """Deactivate (IOCs are kept as the record alerts cite; they stop matching)."""
    return IocOut.model_validate(iocs.deactivate(principal, case_id, ioc_id, meta))

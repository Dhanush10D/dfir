"""Playbooks, runs, approvals and IOC enrichment (guide 15.2, 19). HTTP only; the state machine,
four-eyes rule and locking live in ``services/playbooks.py``, enrichment policy in
``services/enrichment.py``."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Path, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from app.api.dependencies import (
    CurrentPrincipal,
    EnrichmentSvc,
    Meta,
    PlaybookSvc,
    require_permission,
)
from app.core.permissions import Permission, Principal
from app.db.models import ActionRequest, Playbook, PlaybookRun
from app.response.registry import ACTIONS
from app.response.schema import PLAYBOOK_ID_PATTERN, STEP_ID_PATTERN
from app.schemas.response import (
    ActionInfo,
    ActionList,
    ActionRequestList,
    ActionRequestOut,
    CancelRequest,
    DecisionRequest,
    EnrichmentEntry,
    EnrichmentList,
    EnrichmentResult,
    EnrichRequest,
    PlaybookImport,
    PlaybookList,
    PlaybookOut,
    RejectRequest,
    RequestStatus,
    RunCreate,
    RunDetail,
    RunList,
    RunOut,
    SightingResult,
    StepOut,
    StepPatch,
)
from app.services.playbooks import RunView

router = APIRouter(tags=["response"])

RulesManager = Annotated[Principal, Depends(require_permission(Permission.RULES_MANAGE))]
PlaybookId = Annotated[str, Path(pattern=PLAYBOOK_ID_PATTERN, max_length=64)]
StepKey = Annotated[str, Path(pattern=STEP_ID_PATTERN, max_length=32)]


def _playbook(row: Playbook) -> PlaybookOut:
    return PlaybookOut(
        id=row.id,
        title=row.title,
        description=row.description,
        version=row.version,
        enabled=row.enabled,
        origin=row.origin,
        sha256=row.sha256,
        trigger=row.trigger or {},
        phases=list(row.steps or []),
        notify=row.notify or {},
        updated_at=row.updated_at,
    )


def _run(run: PlaybookRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "case_id": run.case_id,
        "playbook_id": run.playbook_id,
        "playbook_version": run.playbook_version,
        "playbook_sha256": run.playbook_sha256,
        "title": str((run.definition or {}).get("title") or run.playbook_id),
        "status": run.status,
        "alert_id": run.alert_id,
        "started_by": run.started_by,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
    }


def _detail(view: RunView) -> RunDetail:
    latest: dict[uuid.UUID, ActionRequest] = {}
    for request in view.requests:  # oldest first: the open request wins, else the last one
        current = latest.get(request.step_id)
        if current is None or current.status not in ("pending", "approved"):
            latest[request.step_id] = request
    steps = []
    for step in view.steps:
        spec = ACTIONS.get(step.action or "")
        newest = latest.get(step.id)
        steps.append(
            StepOut(
                id=step.id,
                position=step.position,
                phase=step.phase,
                step_key=step.step_key,
                text=step.text,
                kind=step.kind,
                action=step.action,
                action_title=spec.title if spec else None,
                executor=spec.executor if spec else None,
                params=step.params or {},
                requires_approval=step.requires_approval,
                status=step.status,
                outcome=step.outcome,
                result=step.result,
                notes=step.notes,
                completed_by=step.completed_by,
                completed_at=step.completed_at,
                updated_by=step.updated_by,
                updated_at=step.updated_at,
                alert_id=view.run.alert_id,
                request=ActionRequestOut.model_validate(newest) if newest else None,
            )
        )
    return RunDetail(**_run(view.run), steps=steps)


# ------------------------------------------------------------------ playbooks


@router.get("/playbooks", response_model=PlaybookList)
def list_playbooks(principal: CurrentPrincipal, playbooks: PlaybookSvc) -> PlaybookList:
    return PlaybookList(items=[_playbook(p) for p in playbooks.list_playbooks(principal)])


@router.post("/playbooks", response_model=PlaybookOut, status_code=201)
def import_playbook(
    body: PlaybookImport, principal: RulesManager, playbooks: PlaybookSvc, meta: Meta
) -> PlaybookOut:
    """Create or update a custom playbook from YAML (strict schema, closed action list)."""
    return _playbook(playbooks.import_yaml(principal, body.yaml, meta))


@router.get("/playbook-actions", response_model=ActionList)
def list_actions(principal: CurrentPrincipal) -> ActionList:
    """The closed registry of actions a playbook step may name."""
    return ActionList(
        items=[
            ActionInfo(
                name=spec.name,
                title=spec.title,
                impact=spec.impact,
                executor=spec.executor,
                effect=spec.effect,
                params={
                    n: {"kind": p.kind, "required": p.required} for n, p in spec.params.items()
                },
            )
            for spec in ACTIONS.values()
        ]
    )


@router.get("/playbooks/{playbook_id}", response_model=PlaybookOut)
def get_playbook(
    playbook_id: PlaybookId, principal: CurrentPrincipal, playbooks: PlaybookSvc
) -> PlaybookOut:
    return _playbook(playbooks.get_playbook(principal, playbook_id))


@router.get("/alerts/{alert_id}/playbooks", response_model=PlaybookList)
def suggest_playbooks(
    alert_id: uuid.UUID, principal: CurrentPrincipal, playbooks: PlaybookSvc
) -> PlaybookList:
    """Playbooks whose trigger matches the alert's rule or ATT&CK techniques."""
    return PlaybookList(items=[_playbook(p) for p in playbooks.suggestions(principal, alert_id)])


# ------------------------------------------------------------------ runs


@router.get("/cases/{case_id}/playbook-runs", response_model=RunList)
def list_runs(case_id: uuid.UUID, principal: CurrentPrincipal, playbooks: PlaybookSvc) -> RunList:
    return RunList(items=[RunOut(**_run(r)) for r in playbooks.list_runs(principal, case_id)])


@router.post("/cases/{case_id}/playbook-runs", response_model=RunDetail, status_code=201)
def start_run(
    case_id: uuid.UUID,
    body: RunCreate,
    principal: CurrentPrincipal,
    playbooks: PlaybookSvc,
    meta: Meta,
) -> Any:
    """Start a playbook. With ``dry_run`` the plan is returned (200) and nothing is written."""
    result = playbooks.start_run(
        principal,
        case_id,
        meta,
        playbook_id=body.playbook_id,
        alert_id=body.alert_id,
        dry_run=body.dry_run,
    )
    if isinstance(result, dict):
        return JSONResponse(status_code=200, content=jsonable_encoder(result))
    return _detail(result)


@router.get("/playbook-runs/{run_id}", response_model=RunDetail)
def get_run(run_id: uuid.UUID, principal: CurrentPrincipal, playbooks: PlaybookSvc) -> RunDetail:
    return _detail(playbooks.get_run(principal, run_id))


@router.patch("/playbook-runs/{run_id}/steps/{step_key}", response_model=RunDetail)
def update_step(
    run_id: uuid.UUID,
    step_key: StepKey,
    body: StepPatch,
    principal: CurrentPrincipal,
    playbooks: PlaybookSvc,
    meta: Meta,
    idempotency_key: Annotated[
        str | None, Header(max_length=128, pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    ] = None,
) -> Any:
    """Complete or skip a step, ask for approval of an action, or execute it."""
    result = playbooks.step_op(
        principal,
        run_id,
        step_key,
        meta,
        op=body.op,
        notes=body.notes,
        params=body.params,
        dry_run=body.dry_run,
        idempotency_key=idempotency_key,
    )
    if isinstance(result, dict):
        return JSONResponse(status_code=200, content=jsonable_encoder(result))
    return _detail(result)


@router.post("/playbook-runs/{run_id}/cancel", response_model=RunDetail)
def cancel_run(
    run_id: uuid.UUID,
    body: CancelRequest,
    principal: CurrentPrincipal,
    playbooks: PlaybookSvc,
    meta: Meta,
) -> RunDetail:
    return _detail(playbooks.cancel_run(principal, run_id, meta, reason=body.reason))


# ------------------------------------------------------------------ approvals


@router.get("/cases/{case_id}/action-requests", response_model=ActionRequestList)
def list_action_requests(
    case_id: uuid.UUID,
    principal: CurrentPrincipal,
    playbooks: PlaybookSvc,
    status: Annotated[RequestStatus | None, Query()] = None,
) -> ActionRequestList:
    rows = playbooks.list_requests(principal, case_id, status)
    return ActionRequestList(items=[ActionRequestOut.model_validate(r) for r in rows])


@router.post("/action-requests/{request_id}/approve", response_model=ActionRequestOut)
def approve_action(
    request_id: uuid.UUID,
    principal: CurrentPrincipal,
    playbooks: PlaybookSvc,
    meta: Meta,
    body: DecisionRequest | None = None,
) -> ActionRequestOut:
    """Four eyes: needs ``approve`` on the case and a different person than the requester."""
    row = playbooks.approve(principal, request_id, meta, reason=body.reason if body else None)
    return ActionRequestOut.model_validate(row)


@router.post("/action-requests/{request_id}/reject", response_model=ActionRequestOut)
def reject_action(
    request_id: uuid.UUID,
    body: RejectRequest,
    principal: CurrentPrincipal,
    playbooks: PlaybookSvc,
    meta: Meta,
) -> ActionRequestOut:
    """Reject (``approve`` permission) or, as the requester, withdraw a pending request."""
    return ActionRequestOut.model_validate(
        playbooks.reject(principal, request_id, meta, reason=body.reason)
    )


# ------------------------------------------------------------------ enrichment


@router.post("/cases/{case_id}/iocs/enrich", response_model=EnrichmentResult)
def enrich_iocs(
    case_id: uuid.UUID,
    body: EnrichRequest,
    principal: CurrentPrincipal,
    enrichment: EnrichmentSvc,
    meta: Meta,
) -> EnrichmentResult:
    """Look case indicators up at the enabled providers (indicators only, within their TLP)."""
    result = enrichment.enrich(
        principal,
        case_id,
        meta,
        ioc_ids=body.ioc_ids,
        providers=body.providers,
        refresh=body.refresh,
    )
    return EnrichmentResult(
        results=[EnrichmentEntry(**entry) for entry in result["results"]],
        counts=result["counts"],
        truncated=result["truncated"],
    )


@router.get("/cases/{case_id}/enrichments", response_model=EnrichmentList)
def list_enrichments(
    case_id: uuid.UUID, principal: CurrentPrincipal, enrichment: EnrichmentSvc
) -> EnrichmentList:
    rows = enrichment.list_cached(principal, case_id)
    return EnrichmentList(items=[EnrichmentEntry(**row) for row in rows])


@router.post("/cases/{case_id}/iocs/{ioc_id}/sighting", response_model=SightingResult)
def export_sighting(
    case_id: uuid.UUID,
    ioc_id: uuid.UUID,
    principal: CurrentPrincipal,
    enrichment: EnrichmentSvc,
    meta: Meta,
) -> SightingResult:
    """Report a sighting of the indicator to MISP (refused beyond its TLP)."""
    return SightingResult(**enrichment.export_sighting(principal, case_id, ioc_id, meta))

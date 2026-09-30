"""AI endpoints (guide 15.2 "AI", 13). HTTP only: access rules, validation, provenance and review
live in ``services/ai.py``; only ``app/ai/gateway.py`` talks to a model."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.dependencies import AiSvc, CurrentPrincipal, Meta
from app.db.models import AiInteraction
from app.schemas.ai import (
    FEATURES,
    AiStatusOut,
    CaseAiSettings,
    ChatRequest,
    CitationOut,
    FeatureOut,
    FeedbackRequest,
    IndexOut,
    InteractionDetail,
    InteractionList,
    InteractionOut,
    NarrativeRequest,
    NlqRequest,
    ReviewRequest,
    ScriptRequest,
)
from app.services.ai import FeatureResult
from app.services.ai_index import IndexInfo

router = APIRouter(prefix="/ai", tags=["ai"])


def _feature_out(result: FeatureResult) -> FeatureOut:
    interaction = InteractionOut.model_validate(result.interaction)
    interaction = interaction.model_copy(update={"warnings": result.outcome.warnings})
    return FeatureOut(
        interaction=interaction,
        output=result.outcome.output,
        citations={k: CitationOut(**v) for k, v in result.citations.items()},
        problems=result.outcome.problems,
        extras=result.extras,
    )


def _detail(row: AiInteraction) -> InteractionDetail:
    base = InteractionOut.model_validate(row).model_dump()
    redactions = row.redactions or {}
    return InteractionDetail(
        **base,
        output=row.output,
        citations=[CitationOut(**c) for c in row.citations or []],
        input_refs=row.input_refs,
        prompt_text=row.prompt_text,
        redaction_policy=redactions.get("policy"),
        redaction_counts=redactions.get("counts") or {},
    )


def _index_out(info: IndexInfo) -> IndexOut:
    return IndexOut.model_validate(info.as_dict())


@router.get("/status", response_model=AiStatusOut)
def ai_status(principal: CurrentPrincipal, ai: AiSvc) -> AiStatusOut:
    return AiStatusOut(**ai.status())


@router.post("/nlq", response_model=FeatureOut)
def nlq(body: NlqRequest, principal: CurrentPrincipal, ai: AiSvc, meta: Meta) -> FeatureOut:
    """A1: translate a question into a search-language query (validated with our grammar)."""
    return _feature_out(ai.nlq(principal, body.case_id, body.question, meta))


@router.post("/alerts/{alert_id}/explain", response_model=FeatureOut)
def explain_alert(
    alert_id: uuid.UUID, principal: CurrentPrincipal, ai: AiSvc, meta: Meta
) -> FeatureOut:
    """A2: explanation, assessment and next steps for an alert, with citations."""
    return _feature_out(ai.explain_alert(principal, alert_id, meta))


@router.post("/cases/{case_id}/narrative", response_model=FeatureOut)
def narrative(
    case_id: uuid.UUID,
    principal: CurrentPrincipal,
    ai: AiSvc,
    meta: Meta,
    body: NarrativeRequest | None = None,
) -> FeatureOut:
    """A3: chronological attack narrative over the key (alert-linked) events."""
    b = body or NarrativeRequest()
    return _feature_out(
        ai.narrative(principal, case_id, meta, start=b.start, end=b.end, host=b.host)
    )


@router.post("/cases/{case_id}/chat", response_model=FeatureOut)
def chat(
    case_id: uuid.UUID, body: ChatRequest, principal: CurrentPrincipal, ai: AiSvc, meta: Meta
) -> FeatureOut:
    """A5: answer from retrieved case evidence (pgvector + full text), or insufficient_evidence."""
    return _feature_out(ai.chat(principal, case_id, body.question, meta))


@router.post("/script/explain", response_model=FeatureOut)
def explain_script(
    body: ScriptRequest, principal: CurrentPrincipal, ai: AiSvc, meta: Meta
) -> FeatureOut:
    """A7: static explanation of a script/command (decoded deterministically; never executed)."""
    return _feature_out(
        ai.explain_script(principal, body.case_id, meta, text=body.text, event_id=body.event_id)
    )


@router.get("/cases/{case_id}/index", response_model=IndexOut)
def index_status(case_id: uuid.UUID, principal: CurrentPrincipal, ai: AiSvc) -> IndexOut:
    return _index_out(ai.index_info(principal, case_id))


@router.post("/cases/{case_id}/index", response_model=IndexOut)
def rebuild_index(
    case_id: uuid.UUID, principal: CurrentPrincipal, ai: AiSvc, meta: Meta
) -> IndexOut:
    return _index_out(ai.rebuild_index(principal, case_id, meta))


@router.put("/cases/{case_id}/settings", response_model=CaseAiSettings)
def case_ai_settings(
    case_id: uuid.UUID, body: CaseAiSettings, principal: CurrentPrincipal, ai: AiSvc, meta: Meta
) -> CaseAiSettings:
    case = ai.set_case_ai(principal, case_id, body.ai_enabled, meta)
    return CaseAiSettings(ai_enabled=case.ai_enabled)


@router.get("/interactions", response_model=InteractionList)
def list_interactions(
    principal: CurrentPrincipal,
    ai: AiSvc,
    case_id: uuid.UUID | None = None,
    feature: FEATURES | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> InteractionList:
    rows, total = ai.list_interactions(
        principal, case_id=case_id, feature=feature, limit=limit, offset=offset
    )
    return InteractionList(
        items=[InteractionOut.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/interactions/{iid}", response_model=InteractionDetail)
def get_interaction(iid: uuid.UUID, principal: CurrentPrincipal, ai: AiSvc) -> InteractionDetail:
    return _detail(ai.get_interaction(principal, iid))


@router.post("/interactions/{iid}/review", response_model=InteractionDetail)
def review(
    iid: uuid.UUID, body: ReviewRequest, principal: CurrentPrincipal, ai: AiSvc, meta: Meta
) -> InteractionDetail:
    """Accept or reject a validated AI output (once; audited). Nothing else is changed."""
    row = ai.review(
        principal,
        iid,
        meta,
        decision=body.decision,
        note=body.note,
        acknowledge_warnings=body.acknowledge_warnings,
    )
    return _detail(row)


@router.post("/interactions/{iid}/feedback", response_model=InteractionOut)
def feedback(
    iid: uuid.UUID, body: FeedbackRequest, principal: CurrentPrincipal, ai: AiSvc, meta: Meta
) -> InteractionOut:
    return InteractionOut.model_validate(ai.feedback(principal, iid, body.value, meta))

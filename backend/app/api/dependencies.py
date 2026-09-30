"""FastAPI dependencies: authentication, route-level RBAC, request metadata, service factories.

Authentication accepts ``Authorization: Bearer <access JWT>`` or ``X-API-Key``. API keys without the
``write`` scope may only use safe methods. The authenticated user id is put on ``request.state`` for
the AuditMiddleware and bound to the structured log context.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Annotated

import structlog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.ai.gateway import Gateway, GatewayConfig, RateLimiter, build_embedding_provider
from app.ai.llm import LLMProvider
from app.config import Settings
from app.core.exceptions import ForbiddenError, UnauthenticatedError
from app.core.permissions import Permission, Principal
from app.core.signing import CustodySigner
from app.deps import (
    get_ai_limiter,
    get_ai_provider_factory,
    get_app_settings,
    get_bundle_dispatcher,
    get_custody_signer,
    get_db,
    get_detect_dispatcher,
    get_job_dispatcher,
    get_trusted_keys,
    get_vault,
)
from app.repositories.vault import VaultStore
from app.services.ai import AiService
from app.services.alerts import AlertService
from app.services.audit import AuditService, RequestMeta
from app.services.authz import require_global
from app.services.bundles import BundleQueryService
from app.services.cases import CaseService
from app.services.custody import CustodyService
from app.services.detection import DetectionJobs
from app.services.entities import EntityService
from app.services.events import EventService
from app.services.evidence import EvidenceService
from app.services.iam import IAMService
from app.services.iocs import IocService
from app.services.jobs import JobService
from app.services.notes import BookmarkService, NoteService
from app.services.proctree import ProcessTreeService, SummaryService
from app.services.rules import RuleService
from app.services.search import SearchService

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_bearer = HTTPBearer(auto_error=False, description="Access token from /auth/login")
_api_key = APIKeyHeader(name="X-API-Key", auto_error=False, description="Personal API key")

DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_app_settings)]


def request_meta(request: Request) -> RequestMeta:
    return RequestMeta(
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        request_id=getattr(request.state, "request_id", None),
    )


Meta = Annotated[RequestMeta, Depends(request_meta)]


def get_iam(db: DbSession, settings: AppSettings) -> IAMService:
    return IAMService(db, settings)


IAM = Annotated[IAMService, Depends(get_iam)]


def current_principal(
    request: Request,
    iam: IAM,
    bearer: Annotated[HTTPAuthorizationCredentials | None, Security(_bearer)],
    api_key: Annotated[str | None, Security(_api_key)],
) -> Principal:
    if bearer is not None and bearer.credentials:
        principal = iam.principal_from_access_token(bearer.credentials)
    elif api_key:
        principal = iam.principal_from_api_key(api_key)
        if "write" not in principal.scopes and request.method not in SAFE_METHODS:
            raise ForbiddenError("This API key is read-only.", scope_required="write")
    else:
        raise UnauthenticatedError()
    request.state.user_id = principal.user_id
    request.state.auth_method = principal.auth_method
    structlog.contextvars.bind_contextvars(user_id=str(principal.user_id))
    return principal


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]


def require_permission(permission: Permission) -> Callable[[Principal], Principal]:
    """Route-level global permission check (services re-check; case scope is service-level)."""

    def dependency(principal: CurrentPrincipal) -> Principal:
        require_global(principal, permission)
        return principal

    return dependency


def get_case_service(db: DbSession, settings: AppSettings) -> CaseService:
    return CaseService(db, settings)


def get_evidence_service(
    db: DbSession,
    settings: AppSettings,
    vault: Annotated[VaultStore | None, Depends(get_vault)],
    signer: Annotated[CustodySigner | None, Depends(get_custody_signer)],
    trusted: Annotated[dict[str, Ed25519PublicKey], Depends(get_trusted_keys)],
) -> EvidenceService:
    return EvidenceService(db, settings, vault=vault, signer=signer, trusted_keys=trusted)


def get_custody_service(db: DbSession) -> CustodyService:
    return CustodyService(db, signer=None)


def get_audit_service(db: DbSession) -> AuditService:
    return AuditService(db)


def get_job_service(
    db: DbSession,
    settings: AppSettings,
    vault: Annotated[VaultStore | None, Depends(get_vault)],
    dispatcher: Annotated[Callable[[uuid.UUID], None], Depends(get_job_dispatcher)],
    detect_dispatcher: Annotated[Callable[[uuid.UUID], None], Depends(get_detect_dispatcher)],
    bundle_dispatcher: Annotated[Callable[[uuid.UUID], None], Depends(get_bundle_dispatcher)],
) -> JobService:
    return JobService(
        db,
        settings,
        vault=vault,
        dispatcher=dispatcher,
        detect_dispatcher=detect_dispatcher,
        bundle_dispatcher=bundle_dispatcher,
    )


def get_event_service(db: DbSession, settings: AppSettings) -> EventService:
    return EventService(db, settings)


def get_detection_jobs(
    db: DbSession,
    settings: AppSettings,
    dispatcher: Annotated[Callable[[uuid.UUID], None], Depends(get_detect_dispatcher)],
) -> DetectionJobs:
    return DetectionJobs(db, settings, dispatcher=dispatcher)


def get_alert_service(db: DbSession, settings: AppSettings) -> AlertService:
    return AlertService(db, settings)


def get_bundle_query_service(db: DbSession, settings: AppSettings) -> BundleQueryService:
    return BundleQueryService(db, settings)


def get_rule_service(db: DbSession) -> RuleService:
    return RuleService(db)


def get_ioc_service(db: DbSession, settings: AppSettings) -> IocService:
    return IocService(db, settings)


def get_search_service(db: DbSession, settings: AppSettings) -> SearchService:
    return SearchService(db, settings)


def get_note_service(db: DbSession, settings: AppSettings) -> NoteService:
    return NoteService(db, settings)


def get_bookmark_service(db: DbSession, settings: AppSettings) -> BookmarkService:
    return BookmarkService(db, settings)


def get_entity_service(db: DbSession, settings: AppSettings) -> EntityService:
    return EntityService(db, settings)


def get_process_tree_service(db: DbSession, settings: AppSettings) -> ProcessTreeService:
    return ProcessTreeService(db, settings)


def get_summary_service(db: DbSession, settings: AppSettings) -> SummaryService:
    return SummaryService(db, settings)


def get_ai_service(
    db: DbSession,
    settings: AppSettings,
    provider_factory: Annotated[
        Callable[[Settings], LLMProvider], Depends(get_ai_provider_factory)
    ],
    limiter: Annotated[RateLimiter, Depends(get_ai_limiter)],
) -> AiService:
    def gateway_factory() -> Gateway:
        embedder = build_embedding_provider(settings)
        return Gateway(
            provider_factory(settings),
            GatewayConfig.from_settings(settings),
            limiter,
            embedder=embedder,
        )

    return AiService(db, settings, gateway_factory=gateway_factory)


AiSvc = Annotated[AiService, Depends(get_ai_service)]
Search = Annotated[SearchService, Depends(get_search_service)]
Notes = Annotated[NoteService, Depends(get_note_service)]
Bookmarks = Annotated[BookmarkService, Depends(get_bookmark_service)]
EntitiesSvc = Annotated[EntityService, Depends(get_entity_service)]
ProcTrees = Annotated[ProcessTreeService, Depends(get_process_tree_service)]
Summaries = Annotated[SummaryService, Depends(get_summary_service)]
Cases = Annotated[CaseService, Depends(get_case_service)]
Detections = Annotated[DetectionJobs, Depends(get_detection_jobs)]
Alerts = Annotated[AlertService, Depends(get_alert_service)]
Rules = Annotated[RuleService, Depends(get_rule_service)]
Iocs = Annotated[IocService, Depends(get_ioc_service)]
Jobs = Annotated[JobService, Depends(get_job_service)]
Bundles = Annotated[BundleQueryService, Depends(get_bundle_query_service)]
Events = Annotated[EventService, Depends(get_event_service)]
EvidenceSvc = Annotated[EvidenceService, Depends(get_evidence_service)]
CustodySvc = Annotated[CustodyService, Depends(get_custody_service)]
AuditSvc = Annotated[AuditService, Depends(get_audit_service)]

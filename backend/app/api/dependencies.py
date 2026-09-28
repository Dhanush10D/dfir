"""FastAPI dependencies: authentication, route-level RBAC, request metadata, service factories.

Authentication accepts ``Authorization: Bearer <access JWT>`` or ``X-API-Key``. API keys without the
``write`` scope may only use safe methods. The authenticated user id is put on ``request.state`` for
the AuditMiddleware and bound to the structured log context.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

import structlog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import ForbiddenError, UnauthenticatedError
from app.core.permissions import Permission, Principal
from app.core.signing import CustodySigner
from app.deps import get_app_settings, get_custody_signer, get_db, get_trusted_keys, get_vault
from app.repositories.vault import VaultStore
from app.services.audit import AuditService, RequestMeta
from app.services.authz import require_global
from app.services.cases import CaseService
from app.services.custody import CustodyService
from app.services.evidence import EvidenceService
from app.services.iam import IAMService

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


Cases = Annotated[CaseService, Depends(get_case_service)]
EvidenceSvc = Annotated[EvidenceService, Depends(get_evidence_service)]
CustodySvc = Annotated[CustodyService, Depends(get_custody_service)]
AuditSvc = Annotated[AuditService, Depends(get_audit_service)]

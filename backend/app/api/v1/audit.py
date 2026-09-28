"""/audit: query the append-only audit log (admins and auditors, guide 15.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import AuditSvc, require_permission
from app.core.permissions import Permission, Principal
from app.schemas.audit import AuditEntryOut, AuditList

router = APIRouter(tags=["audit"])

AuditViewer = Annotated[Principal, Depends(require_permission(Permission.AUDIT_VIEW))]


@router.get("/audit", response_model=AuditList)
def query_audit(
    principal: AuditViewer,
    audit: AuditSvc,
    user_id: uuid.UUID | None = None,
    action: Annotated[str | None, Query(max_length=100)] = None,
    object_type: Annotated[str | None, Query(max_length=50)] = None,
    object_id: Annotated[str | None, Query(max_length=100)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditList:
    rows, total = audit.query(
        user_id=user_id,
        action=action,
        object_type=object_type,
        object_id=object_id,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
    return AuditList(items=[AuditEntryOut.model_validate(r) for r in rows], total=total)

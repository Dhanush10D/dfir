"""/cases: create, list, read, update, close, members. HTTP only; logic in services/cases.py."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.dependencies import Cases, CurrentPrincipal, Meta, require_permission
from app.core.permissions import Permission, Principal
from app.db.models import CaseStatus
from app.schemas.cases import (
    CaseClose,
    CaseCreate,
    CaseDetail,
    CaseList,
    CaseOut,
    CaseUpdate,
    MemberOut,
    MemberSet,
)
from app.services.authz import CaseAccess

router = APIRouter(prefix="/cases", tags=["cases"])

CaseCreator = Annotated[Principal, Depends(require_permission(Permission.CASE_CREATE))]


def _detail(access: CaseAccess) -> CaseDetail:
    out = CaseOut.model_validate(access.case)
    return CaseDetail(
        **out.model_dump(),
        my_case_role=access.case_role,
        my_permissions=sorted(p.value for p in access.permissions),
    )


@router.get("", response_model=CaseList)
def list_cases(
    principal: CurrentPrincipal,
    cases: Cases,
    status_filter: Annotated[CaseStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> CaseList:
    rows, total = cases.list_cases(principal, status=status_filter, limit=limit, offset=offset)
    return CaseList(items=[CaseOut.model_validate(c) for c in rows], total=total)


@router.post("", response_model=CaseDetail, status_code=status.HTTP_201_CREATED)
def create_case(body: CaseCreate, principal: CaseCreator, cases: Cases, meta: Meta) -> CaseDetail:
    case = cases.create(
        principal,
        title=body.title,
        description=body.description,
        severity=body.severity,
        classification=body.classification,
        case_number=body.case_number,
        meta=meta,
    )
    return _detail(cases.access(principal, case.id))


@router.get("/{case_id}", response_model=CaseDetail)
def get_case(case_id: uuid.UUID, principal: CurrentPrincipal, cases: Cases) -> CaseDetail:
    return _detail(cases.access(principal, case_id))


@router.patch("/{case_id}", response_model=CaseDetail)
def update_case(
    case_id: uuid.UUID, body: CaseUpdate, principal: CurrentPrincipal, cases: Cases, meta: Meta
) -> CaseDetail:
    cases.update(principal, case_id, meta=meta, changes=body.model_dump(exclude_unset=True))
    return _detail(cases.access(principal, case_id))


@router.post("/{case_id}/close", response_model=CaseDetail)
def close_case(
    case_id: uuid.UUID, body: CaseClose, principal: CurrentPrincipal, cases: Cases, meta: Meta
) -> CaseDetail:
    cases.close(principal, case_id, body.reason, meta)
    return _detail(cases.access(principal, case_id))


@router.get("/{case_id}/members", response_model=list[MemberOut])
def list_members(case_id: uuid.UUID, principal: CurrentPrincipal, cases: Cases) -> list[MemberOut]:
    return [
        MemberOut(
            user_id=u.id,
            email=u.email,
            display_name=u.display_name,
            global_role=u.role,
            case_role=m.role,
        )
        for m, u in cases.members(principal, case_id)
    ]


@router.post("/{case_id}/members", response_model=list[MemberOut])
def set_member(
    case_id: uuid.UUID, body: MemberSet, principal: CurrentPrincipal, cases: Cases, meta: Meta
) -> list[MemberOut]:
    cases.add_member(principal, case_id, body.user_id, body.role, meta)
    return list_members(case_id, principal, cases)


@router.delete("/{case_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    case_id: uuid.UUID, user_id: uuid.UUID, principal: CurrentPrincipal, cases: Cases, meta: Meta
) -> Response:
    cases.remove_member(principal, case_id, user_id, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

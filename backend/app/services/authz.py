"""Service-level authorization (guide 16.3): defense in depth behind the route-level checks.

Object-level rule: a case the caller cannot read is reported as *not found* (no IDOR oracle);
a readable case where the action is not allowed is *forbidden*.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import ForbiddenError, NotFoundError
from app.core.permissions import Permission, Principal, effective_case_permissions
from app.db.models import Case, CaseMember, UserRole


def require_global(principal: Principal, permission: Permission) -> None:
    if not principal.can(permission):
        raise ForbiddenError(
            "Your role does not allow this action.",
            permission=permission.value,
            role=principal.role.value,
        )


@dataclass(frozen=True)
class CaseAccess:
    case: Case
    case_role: UserRole | None
    permissions: frozenset[Permission]

    def require(self, permission: Permission) -> None:
        if permission not in self.permissions:
            raise ForbiddenError(
                "Your role on this case does not allow this action.",
                permission=permission.value,
            )


def case_role_of(session: Session, case_id: uuid.UUID, user_id: uuid.UUID) -> UserRole | None:
    return session.execute(
        select(CaseMember.role).where(CaseMember.case_id == case_id, CaseMember.user_id == user_id)
    ).scalar_one_or_none()


def load_case_access(
    session: Session,
    principal: Principal,
    case_id: uuid.UUID,
    *,
    auditor_all_cases: bool = True,
    lock: bool = False,
) -> CaseAccess:
    stmt = select(Case).where(Case.id == case_id)
    if lock:
        stmt = stmt.with_for_update()
    case = session.execute(stmt).scalar_one_or_none()
    if case is None:
        raise NotFoundError("Case not found.")
    role = case_role_of(session, case_id, principal.user_id)
    perms = effective_case_permissions(principal.role, role, auditor_all_cases)
    if Permission.CASE_READ not in perms:
        raise NotFoundError("Case not found.")
    return CaseAccess(case=case, case_role=role, permissions=perms)

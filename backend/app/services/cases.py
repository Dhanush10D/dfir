"""Case management (guide 14.4 CaseService): create, list, update with validated transitions,
members, close."""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import AppError, ConflictError, InvalidStateError, NotFoundError
from app.core.permissions import Permission, Principal, has_global_access
from app.db.models import (
    Case,
    CaseMember,
    CaseStatus,
    Evidence,
    Job,
    JobStatus,
    Severity,
    User,
    UserRole,
)
from app.services.audit import AuditService, RequestMeta
from app.services.authz import CaseAccess, load_case_access, require_global

# Incident-response lifecycle order (guide 2.1). Moving forward may skip phases; moving back is one
# step at a time; ``closed`` is reached only through close() and left only by a reopen to ``open``.
LIFECYCLE = [
    CaseStatus.open,
    CaseStatus.triage,
    CaseStatus.containment,
    CaseStatus.eradication,
    CaseStatus.recovery,
    CaseStatus.post_incident,
]
CASE_NUMBER_RE = re.compile(r"^[A-Z]{2,8}-\d{4}-\d{4,6}$")
UNFINALIZED_EVIDENCE = ("uploading", "uploaded")


def transition_allowed(current: CaseStatus, target: CaseStatus) -> bool:
    if current == target:
        return True
    if current is CaseStatus.closed:
        return target is CaseStatus.open
    if target is CaseStatus.closed:
        return False
    i, j = LIFECYCLE.index(current), LIFECYCLE.index(target)
    return j > i or j == i - 1


def utcnow() -> datetime:
    return datetime.now(UTC)


class CaseService:
    def __init__(
        self, session: Session, settings: Settings, clock: Callable[[], datetime] = utcnow
    ) -> None:
        self.session = session
        self.settings = settings
        self.clock = clock
        self.audit = AuditService(session)

    def access(self, principal: Principal, case_id: uuid.UUID, lock: bool = False) -> CaseAccess:
        return load_case_access(
            self.session,
            principal,
            case_id,
            auditor_all_cases=self.settings.auditor_all_cases,
            lock=lock,
        )

    def _next_case_number(self) -> str:
        year = self.clock().year
        prefix = f"IR-{year}-"
        # Serialize numbering across concurrent creators for the rest of this transaction.
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"dfir_case_number:{year}"}
        )
        numbers = self.session.execute(
            select(Case.case_number).where(Case.case_number.like(f"{prefix}%"))
        ).scalars()
        highest = max(
            (int(n.rsplit("-", 1)[1]) for n in numbers if n.rsplit("-", 1)[1].isdigit()), default=0
        )
        return f"{prefix}{highest + 1:04d}"

    def create(
        self,
        principal: Principal,
        *,
        title: str,
        meta: RequestMeta,
        description: str | None = None,
        severity: Severity = Severity.medium,
        classification: str | None = None,
        case_number: str | None = None,
    ) -> Case:
        require_global(principal, Permission.CASE_CREATE)
        if case_number is not None and not CASE_NUMBER_RE.fullmatch(case_number):
            raise AppError("invalid_case_number", "Case number must look like IR-2026-0001.", 422)
        case = Case(
            id=uuid.uuid4(),
            case_number=case_number or self._next_case_number(),
            title=title.strip(),
            description=description,
            severity=severity,
            classification=classification or "confidential",
            created_by=principal.user_id,
            lead_id=principal.user_id
            if principal.role in (UserRole.lead, UserRole.admin)
            else None,
        )
        self.session.add(case)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError("Case number already exists.", "case_number_taken") from exc
        # The creator becomes a case lead; effective rights are still capped by the global role.
        self.session.add(CaseMember(case_id=case.id, user_id=principal.user_id, role=UserRole.lead))
        self.audit.record(
            "case.created",
            user_id=principal.user_id,
            meta=meta,
            object_type="case",
            object_id=case.id,
            detail={"case_number": case.case_number},
        )
        self.session.commit()
        return case

    def list_cases(
        self,
        principal: Principal,
        *,
        status: CaseStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Case], int]:
        conditions: list[Any] = []
        if status is not None:
            conditions.append(Case.status == status)
        if not has_global_access(principal.role, self.settings.auditor_all_cases):
            member_cases = select(CaseMember.case_id).where(CaseMember.user_id == principal.user_id)
            conditions.append(Case.id.in_(member_cases))
        total = self.session.execute(
            select(func.count()).select_from(Case).where(*conditions)
        ).scalar_one()
        rows = self.session.execute(
            select(Case)
            .where(*conditions)
            .order_by(Case.opened_at.desc(), Case.case_number.desc())
            .limit(limit)
            .offset(offset)
        ).scalars()
        return list(rows), int(total)

    def update(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        *,
        meta: RequestMeta,
        changes: dict[str, Any],
    ) -> Case:
        access = self.access(principal, case_id, lock=True)
        access.require(Permission.CASE_UPDATE)
        case = access.case
        applied: dict[str, Any] = {}
        status = changes.pop("status", None)
        lead_id = changes.pop("lead_id", None)
        if case.status is CaseStatus.closed and status is not CaseStatus.open:
            # Only a reopen (status -> open, needs case:manage) may touch a closed case.
            raise InvalidStateError("Closed cases are read-only; reopen the case first.")
        if status is not None and status != case.status:
            if not transition_allowed(case.status, status):
                raise InvalidStateError(
                    f"Status cannot change from {case.status.value} to {status.value}.",
                    allowed=[s.value for s in CaseStatus if transition_allowed(case.status, s)],
                )
            if case.status is CaseStatus.closed:
                access.require(Permission.CASE_MANAGE)  # reopen
                case.closed_at = None
            applied["status"] = {"from": case.status.value, "to": status.value}
            case.status = status
        if lead_id is not None and lead_id != case.lead_id:
            access.require(Permission.CASE_MANAGE)
            if self.session.get(User, lead_id) is None:
                raise NotFoundError("Lead user not found.")
            applied["lead_id"] = str(lead_id)
            case.lead_id = lead_id
        for field_name in ("title", "description", "severity", "classification"):
            if field_name in changes and changes[field_name] != getattr(case, field_name):
                setattr(case, field_name, changes[field_name])
                value = changes[field_name]
                applied[field_name] = value.value if isinstance(value, Severity) else value
        if applied:
            self.audit.record(
                "case.updated",
                user_id=principal.user_id,
                meta=meta,
                object_type="case",
                object_id=case.id,
                detail=applied,
            )
        self.session.commit()
        return case

    def close(
        self, principal: Principal, case_id: uuid.UUID, reason: str | None, meta: RequestMeta
    ) -> Case:
        access = self.access(principal, case_id, lock=True)
        access.require(Permission.CASE_MANAGE)
        case = access.case
        if case.status is CaseStatus.closed:
            raise InvalidStateError("Case is already closed.")
        pending = self.session.execute(
            select(Evidence.label).where(
                Evidence.case_id == case.id, Evidence.status.in_(UNFINALIZED_EVIDENCE)
            )
        ).scalars()
        pending_labels = sorted(pending)
        if pending_labels:
            raise InvalidStateError("Evidence uploads are not finalized.", evidence=pending_labels)
        # Job submission holds FOR SHARE on this (now FOR UPDATE-locked) row while it inserts, so
        # this check sees every job that can still write to the case.
        active_jobs = [
            str(j)
            for j in self.session.execute(
                select(Job.id)
                .where(
                    Job.case_id == case.id,
                    Job.status.in_((JobStatus.queued, JobStatus.running)),
                )
                .limit(20)
            ).scalars()
        ]
        if active_jobs:
            raise InvalidStateError(
                "Processing jobs are still queued or running; wait or cancel them first.",
                jobs=active_jobs,
            )
        previous = case.status
        case.status = CaseStatus.closed
        case.closed_at = self.clock()
        self.audit.record(
            "case.closed",
            user_id=principal.user_id,
            meta=meta,
            object_type="case",
            object_id=case.id,
            detail={"from": previous.value, "reason": reason},
        )
        self.session.commit()
        return case

    def members(self, principal: Principal, case_id: uuid.UUID) -> list[tuple[CaseMember, User]]:
        self.access(principal, case_id)
        rows = self.session.execute(
            select(CaseMember, User)
            .join(User, User.id == CaseMember.user_id)
            .where(CaseMember.case_id == case_id)
            .order_by(User.email)
        ).all()
        return [(m, u) for m, u in rows]

    def add_member(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        user_id: uuid.UUID,
        role: UserRole,
        meta: RequestMeta,
    ) -> CaseMember:
        access = self.access(principal, case_id, lock=True)
        access.require(Permission.CASE_MANAGE)
        user = self.session.get(User, user_id)
        if user is None or not user.is_active:
            raise NotFoundError("User not found.")
        member = self.session.get(CaseMember, (case_id, user_id))
        previous = member.role.value if member else None
        if member is None:
            member = CaseMember(case_id=case_id, user_id=user_id, role=role)
            self.session.add(member)
        else:
            member.role = role
        self.audit.record(
            "case.member_set",
            user_id=principal.user_id,
            meta=meta,
            object_type="case",
            object_id=case_id,
            detail={"member": str(user_id), "role": role.value, "previous": previous},
        )
        self.session.commit()
        return member

    def remove_member(
        self, principal: Principal, case_id: uuid.UUID, user_id: uuid.UUID, meta: RequestMeta
    ) -> None:
        access = self.access(principal, case_id, lock=True)
        access.require(Permission.CASE_MANAGE)
        member = self.session.get(CaseMember, (case_id, user_id))
        if member is None:
            raise NotFoundError("Member not found.")
        self.session.delete(member)
        self.audit.record(
            "case.member_removed",
            user_id=principal.user_id,
            meta=meta,
            object_type="case",
            object_id=case_id,
            detail={"member": str(user_id)},
        )
        self.session.commit()

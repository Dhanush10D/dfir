"""RBAC policy (guide 16.1, 16.3): the role x permission table, case-role capping, principals.

Effective permission on a case = global role permissions ∩ case-level role permissions. Admins
(and auditors when ``AUDITOR_ALL_CASES``) act on every case with their global role and need no
membership. Global permissions (user management, case creation, audit log) are never capped.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field

from app.db.models.enums import UserRole


class Permission(enum.StrEnum):
    USERS_MANAGE = "users:manage"  # manage users, settings, integrations
    CASE_CREATE = "case:create"
    CASE_READ = "case:read"  # read case data
    CASE_UPDATE = "case:update"  # edit case fields, move status forward/back
    CASE_MANAGE = "case:manage"  # members, close, reopen
    EVIDENCE_ADD = "evidence:add"  # create records, upload, finalize, run jobs
    EVIDENCE_VERIFY = "evidence:verify"
    EVIDENCE_DOWNLOAD = "evidence:download"  # download original evidence
    CUSTODY_VIEW = "custody:view"
    INVESTIGATE = "investigate"  # search, notes, bookmarks
    ALERT_UPDATE = "alert:update"
    APPROVE = "approve"  # approve reports, destructive actions
    AUDIT_VIEW = "audit:view"
    AI_USE = "ai:use"
    RULES_MANAGE = "rules:manage"  # create/update/enable/disable/import detection rules (global)


P = Permission

# Guide 16.1, with documented choices (docs/specs/PHASE-1.md, PHASE-3.md):
# - AUDIT_VIEW (the global /audit log) follows endpoint table 15.2: admin + auditor.
# - CUSTODY_VIEW includes analysts, who add and verify evidence and need to see its chain.
# - RULES_MANAGE (global) follows endpoint table 15.2 (/rules writes: lead + admin).
ROLE_PERMISSIONS: dict[UserRole, frozenset[Permission]] = {
    UserRole.admin: frozenset(Permission),
    UserRole.lead: frozenset(
        {
            P.CASE_CREATE,
            P.CASE_READ,
            P.CASE_UPDATE,
            P.CASE_MANAGE,
            P.EVIDENCE_ADD,
            P.EVIDENCE_VERIFY,
            P.EVIDENCE_DOWNLOAD,
            P.CUSTODY_VIEW,
            P.INVESTIGATE,
            P.ALERT_UPDATE,
            P.APPROVE,
            P.AI_USE,
            P.RULES_MANAGE,
        }
    ),
    UserRole.analyst: frozenset(
        {
            P.CASE_CREATE,
            P.CASE_READ,
            P.CASE_UPDATE,
            P.EVIDENCE_ADD,
            P.EVIDENCE_VERIFY,
            P.CUSTODY_VIEW,
            P.INVESTIGATE,
            P.ALERT_UPDATE,
            P.AI_USE,
        }
    ),
    UserRole.viewer: frozenset({P.CASE_READ}),
    UserRole.auditor: frozenset(
        {P.CASE_READ, P.EVIDENCE_VERIFY, P.EVIDENCE_DOWNLOAD, P.CUSTODY_VIEW, P.AUDIT_VIEW}
    ),
}

GLOBAL_PERMISSIONS = frozenset({P.USERS_MANAGE, P.CASE_CREATE, P.AUDIT_VIEW, P.RULES_MANAGE})


def permissions_for(role: UserRole) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[role]


def has_global_access(role: UserRole, auditor_all_cases: bool = True) -> bool:
    """Roles that see every case without membership."""
    return role is UserRole.admin or (role is UserRole.auditor and auditor_all_cases)


def effective_case_permissions(
    global_role: UserRole, case_role: UserRole | None, auditor_all_cases: bool = True
) -> frozenset[Permission]:
    """Permissions a user has on one case. Empty set = no access (callers answer 404)."""
    base = ROLE_PERMISSIONS[global_role] - GLOBAL_PERMISSIONS
    if has_global_access(global_role, auditor_all_cases):
        return base
    if case_role is None:
        return frozenset()
    return base & ROLE_PERMISSIONS[case_role]


@dataclass(frozen=True)
class Principal:
    """The authenticated caller, as seen by services (no web-framework types)."""

    user_id: uuid.UUID
    email: str
    display_name: str
    role: UserRole
    auth_method: str = "jwt"  # jwt | api_key | system
    scopes: frozenset[str] = field(default_factory=frozenset)  # API keys only
    api_key_id: uuid.UUID | None = None

    @property
    def label(self) -> str:
        """Name recorded in custody entries at the time of the action."""
        return f"{self.display_name} <{self.email}>"

    def can(self, permission: Permission) -> bool:
        return permission in ROLE_PERMISSIONS[self.role]

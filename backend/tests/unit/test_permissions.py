"""Every cell of the role x permission table (guide 16.3), plus case-role capping."""

from __future__ import annotations

import uuid

import pytest

from app.core.permissions import (
    GLOBAL_PERMISSIONS,
    ROLE_PERMISSIONS,
    Permission,
    Principal,
    effective_case_permissions,
    has_global_access,
)
from app.db.models import UserRole

P = Permission
A, L, N, V, U = (
    UserRole.admin,
    UserRole.lead,
    UserRole.analyst,
    UserRole.viewer,
    UserRole.auditor,
)

# Expected table (guide 16.1 with the documented AUDIT_VIEW/CUSTODY_VIEW choices).
TABLE: dict[Permission, set[UserRole]] = {
    P.USERS_MANAGE: {A},
    P.CASE_CREATE: {A, L, N},
    P.CASE_READ: {A, L, N, V, U},
    P.CASE_UPDATE: {A, L, N},
    P.CASE_MANAGE: {A, L},
    P.EVIDENCE_ADD: {A, L, N},
    P.EVIDENCE_VERIFY: {A, L, N, U},
    P.EVIDENCE_DOWNLOAD: {A, L, U},
    P.CUSTODY_VIEW: {A, L, N, U},
    P.INVESTIGATE: {A, L, N},
    P.ALERT_UPDATE: {A, L, N},
    P.APPROVE: {A, L},
    P.AUDIT_VIEW: {A, U},
    P.AI_USE: {A, L, N},
    P.RULES_MANAGE: {A, L},
}

CELLS = [(perm, role) for perm in Permission for role in UserRole]


def test_table_covers_every_permission() -> None:
    assert set(TABLE) == set(Permission)
    assert set(ROLE_PERMISSIONS) == set(UserRole)


@pytest.mark.parametrize(
    ("permission", "role"), CELLS, ids=[f"{p.value}-{r.value}" for p, r in CELLS]
)
def test_cell(permission: Permission, role: UserRole) -> None:
    assert (permission in ROLE_PERMISSIONS[role]) == (role in TABLE[permission])


def test_viewer_is_read_only() -> None:
    assert ROLE_PERMISSIONS[V] == {P.CASE_READ}


def test_global_access() -> None:
    assert has_global_access(A)
    assert has_global_access(U)
    assert not has_global_access(U, auditor_all_cases=False)
    for role in (L, N, V):
        assert not has_global_access(role)


def test_non_members_have_no_case_access() -> None:
    for role in (L, N, V):
        assert effective_case_permissions(role, None) == frozenset()
    assert effective_case_permissions(U, None, auditor_all_cases=False) == frozenset()


def test_admin_and_auditor_use_global_role_on_every_case() -> None:
    assert effective_case_permissions(A, None) == frozenset(Permission) - GLOBAL_PERMISSIONS
    auditor = effective_case_permissions(U, UserRole.viewer)
    assert P.EVIDENCE_DOWNLOAD in auditor and P.EVIDENCE_ADD not in auditor


@pytest.mark.parametrize("global_role", [L, N, V])
@pytest.mark.parametrize("case_role", list(UserRole))
def test_case_role_caps_global_role(global_role: UserRole, case_role: UserRole) -> None:
    effective = effective_case_permissions(global_role, case_role)
    assert effective == (ROLE_PERMISSIONS[global_role] & ROLE_PERMISSIONS[case_role]) - (
        GLOBAL_PERMISSIONS
    )
    # Capping never grants more than the global role.
    assert effective <= ROLE_PERMISSIONS[global_role]


def test_principal_helpers() -> None:
    p = Principal(uuid.uuid4(), "a@b.c", "Ann", UserRole.analyst)
    assert p.label == "Ann <a@b.c>"
    assert p.can(P.EVIDENCE_ADD) and not p.can(P.USERS_MANAGE)

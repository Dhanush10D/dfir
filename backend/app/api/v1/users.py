"""/me (self-service: profile, password, MFA, sessions, API keys) and /users (admin)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from app.api.dependencies import IAM, CurrentPrincipal, Meta, require_permission
from app.core.permissions import Permission, Principal, permissions_for
from app.schemas.auth import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    MeResponse,
    MfaConfirmRequest,
    MfaDisableRequest,
    MfaEnrollResponse,
    PasswordChangeRequest,
    ReauthRequest,
    RecoveryCodesResponse,
    SessionOut,
    UserCreate,
    UserOut,
    UserUpdate,
)

router = APIRouter(tags=["users"])

Admin = Annotated[Principal, Depends(require_permission(Permission.USERS_MANAGE))]


@router.get("/me", response_model=MeResponse)
def me(principal: CurrentPrincipal, iam: IAM) -> MeResponse:
    user = iam.get_user(principal.user_id)
    return MeResponse(
        user=UserOut.model_validate(user),
        permissions=sorted(p.value for p in permissions_for(principal.role)),
        auth_method=principal.auth_method,
    )


@router.get("/me/sessions", response_model=list[SessionOut])
def my_sessions(principal: CurrentPrincipal, iam: IAM) -> list[SessionOut]:
    return [SessionOut(**vars(s)) for s in iam.sessions(principal)]


@router.post("/me/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: PasswordChangeRequest, principal: CurrentPrincipal, iam: IAM, meta: Meta
) -> Response:
    iam.change_password(principal, body.current_password, body.new_password, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/me/mfa/enroll", response_model=MfaEnrollResponse)
def mfa_enroll(principal: CurrentPrincipal, iam: IAM, meta: Meta) -> MfaEnrollResponse:
    enrollment = iam.mfa_enroll(principal, meta)
    return MfaEnrollResponse(secret=enrollment.secret, otpauth_uri=enrollment.otpauth_uri)


@router.post("/me/mfa/confirm", response_model=RecoveryCodesResponse)
def mfa_confirm(
    body: MfaConfirmRequest, principal: CurrentPrincipal, iam: IAM, meta: Meta
) -> RecoveryCodesResponse:
    return RecoveryCodesResponse(recovery_codes=iam.mfa_confirm(principal, body.code, meta))


@router.post("/me/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
def mfa_disable(
    body: MfaDisableRequest, principal: CurrentPrincipal, iam: IAM, meta: Meta
) -> Response:
    iam.mfa_disable(principal, body.password, body.code, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me/api-keys", response_model=list[ApiKeyOut])
def list_api_keys(principal: CurrentPrincipal, iam: IAM) -> list[ApiKeyOut]:
    return [ApiKeyOut.model_validate(k) for k in iam.list_api_keys(principal)]


@router.post("/me/api-keys", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_api_key(
    body: ApiKeyCreate, principal: CurrentPrincipal, iam: IAM, meta: Meta
) -> ApiKeyCreated:
    created = iam.create_api_key(
        principal, body.name, list(body.scopes), body.expires_in_days, meta
    )
    out = ApiKeyOut.model_validate(created.record)
    return ApiKeyCreated(**out.model_dump(), key=created.key)


@router.delete("/me/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_key(
    key_id: uuid.UUID, principal: CurrentPrincipal, iam: IAM, meta: Meta
) -> Response:
    iam.revoke_api_key(principal, key_id, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/users", response_model=list[UserOut])
def list_users(principal: Admin, iam: IAM) -> list[UserOut]:
    return [UserOut.model_validate(u) for u in iam.list_users(principal)]


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, principal: Admin, iam: IAM, meta: Meta) -> UserOut:
    user = iam.create_user(
        principal,
        email=body.email,
        display_name=body.display_name,
        role=body.role,
        password=body.password,
        meta=meta,
        admin_password=body.admin_password,
    )
    return UserOut.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID, body: UserUpdate, principal: Admin, iam: IAM, meta: Meta
) -> UserOut:
    user = iam.update_user(
        principal,
        user_id,
        meta=meta,
        display_name=body.display_name,
        role=body.role,
        is_active=body.is_active,
        reset_mfa=body.reset_mfa,
        unlock=body.unlock,
        admin_password=body.admin_password,
    )
    return UserOut.model_validate(user)


@router.delete("/users/{user_id}", response_model=UserOut)
def deactivate_user(
    user_id: uuid.UUID, body: ReauthRequest, principal: Admin, iam: IAM, meta: Meta
) -> UserOut:
    """Deactivate (users are never hard-deleted: custody and audit rows reference them)."""
    user = iam.update_user(
        principal, user_id, meta=meta, is_active=False, admin_password=body.admin_password
    )
    return UserOut.model_validate(user)

"""/auth: login, MFA completion, token refresh, logout. HTTP only; logic in services/iam.py."""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from app.api.dependencies import IAM, CurrentPrincipal, Meta
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    MfaVerifyRequest,
    RefreshRequest,
    TokenResponse,
)
from app.schemas.health import ErrorResponse
from app.services.iam import TokenPair

router = APIRouter(prefix="/auth", tags=["auth"])

ERRORS: dict[int | str, dict[str, object]] = {
    401: {"model": ErrorResponse},
    429: {"model": ErrorResponse, "description": "Account temporarily locked"},
}


def _tokens(pair: TokenPair) -> TokenResponse:
    return TokenResponse(
        access_token=pair.access_token,
        expires_at=pair.access_expires_at,
        refresh_token=pair.refresh_token,
        refresh_expires_at=pair.refresh_expires_at,
    )


@router.post("/login", response_model=LoginResponse, responses=ERRORS)
def login(body: LoginRequest, iam: IAM, meta: Meta) -> LoginResponse:
    result = iam.login(body.email, body.password, meta)
    if result.tokens is None:
        return LoginResponse(
            mfa_required=True,
            mfa_challenge=result.mfa_challenge,
            mfa_expires_at=result.mfa_expires_at,
        )
    return LoginResponse(tokens=_tokens(result.tokens))


@router.post("/mfa/verify", response_model=TokenResponse, responses=ERRORS)
def mfa_verify(body: MfaVerifyRequest, iam: IAM, meta: Meta) -> TokenResponse:
    pair = iam.verify_mfa(
        body.mfa_challenge, meta, code=body.code, recovery_code=body.recovery_code
    )
    return _tokens(pair)


@router.post("/refresh", response_model=TokenResponse, responses=ERRORS)
def refresh(body: RefreshRequest, iam: IAM, meta: Meta) -> TokenResponse:
    return _tokens(iam.refresh(body.refresh_token, meta))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: RefreshRequest, iam: IAM, meta: Meta) -> Response:
    iam.logout(body.refresh_token, meta)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout-all")
def logout_all(principal: CurrentPrincipal, iam: IAM, meta: Meta) -> dict[str, int]:
    """Revoke every refresh token of the caller ("log out everywhere")."""
    return {"revoked": iam.logout_all(principal, meta)}

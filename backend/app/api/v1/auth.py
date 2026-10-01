"""/auth: login, MFA completion, token refresh, logout. HTTP only; logic in services/iam.py.

Token delivery (guide 16.4, 17.4 "no tokens in localStorage"):

* default (API clients): access and refresh token in the JSON body, refresh/logout take
  ``{"refresh_token"}`` in the body.
* browser: send ``X-Token-Delivery: cookie``. The refresh token is then set only as an
  ``HttpOnly; Secure; SameSite=Strict`` cookie scoped to ``/api/v1/auth`` and is *omitted* from
  the JSON body; the SPA keeps the short-lived access token in memory. ``/auth/refresh`` and
  ``/auth/logout`` read the cookie only when the same header is present: a custom header cannot be
  sent cross-site without a CORS preflight (allowed origins only), which together with
  SameSite=Strict is the CSRF defence.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request, Response, status

from app.api.dependencies import IAM, AppSettings, CurrentPrincipal, Meta
from app.config import Settings
from app.core.exceptions import UnauthenticatedError
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

DELIVERY_HEADER = "X-Token-Delivery"
COOKIE_PATH = "/api/v1/auth"
ERRORS: dict[int | str, dict[str, object]] = {
    401: {"model": ErrorResponse},
    429: {"model": ErrorResponse, "description": "Account locked or too many attempts (per IP)"},
}


def wants_cookie(request: Request) -> bool:
    return request.headers.get(DELIVERY_HEADER, "").strip().lower() == "cookie"


def set_refresh_cookie(response: Response, settings: Settings, pair: TokenPair) -> None:
    max_age = max(int((pair.refresh_expires_at - datetime.now(UTC)).total_seconds()), 0)
    response.set_cookie(
        settings.auth_cookie_name,
        pair.refresh_token,
        max_age=max_age,
        path=COOKIE_PATH,
        secure=settings.auth_cookie_secure,
        httponly=True,
        samesite="strict",
    )


def clear_refresh_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        settings.auth_cookie_name,
        path=COOKIE_PATH,
        secure=settings.auth_cookie_secure,
        httponly=True,
        samesite="strict",
    )


def _tokens(
    pair: TokenPair, request: Request, response: Response, settings: Settings
) -> TokenResponse:
    if wants_cookie(request):
        set_refresh_cookie(response, settings, pair)
        response.headers["Cache-Control"] = "no-store"
        refresh: str | None = None
    else:
        refresh = pair.refresh_token
    return TokenResponse(
        access_token=pair.access_token,
        expires_at=pair.access_expires_at,
        refresh_token=refresh,
        refresh_expires_at=pair.refresh_expires_at,
    )


def _refresh_token(body: RefreshRequest | None, request: Request, settings: Settings) -> str | None:
    if body is not None:
        return body.refresh_token
    if wants_cookie(request):
        token = request.cookies.get(settings.auth_cookie_name)
        if token and 10 <= len(token) <= 512:
            return token
    return None


@router.post("/login", response_model=LoginResponse, responses=ERRORS)
def login(
    body: LoginRequest,
    iam: IAM,
    meta: Meta,
    request: Request,
    response: Response,
    settings: AppSettings,
) -> LoginResponse:
    iam.limit_attempts("login", meta)
    result = iam.login(body.email, body.password, meta)
    if result.tokens is None:
        return LoginResponse(
            mfa_required=True,
            mfa_challenge=result.mfa_challenge,
            mfa_expires_at=result.mfa_expires_at,
        )
    return LoginResponse(tokens=_tokens(result.tokens, request, response, settings))


@router.post("/mfa/verify", response_model=TokenResponse, responses=ERRORS)
def mfa_verify(
    body: MfaVerifyRequest,
    iam: IAM,
    meta: Meta,
    request: Request,
    response: Response,
    settings: AppSettings,
) -> TokenResponse:
    iam.limit_attempts("login", meta)
    pair = iam.verify_mfa(
        body.mfa_challenge, meta, code=body.code, recovery_code=body.recovery_code
    )
    return _tokens(pair, request, response, settings)


@router.post("/refresh", response_model=TokenResponse, responses=ERRORS)
def refresh(
    iam: IAM,
    meta: Meta,
    request: Request,
    response: Response,
    settings: AppSettings,
    body: RefreshRequest | None = None,
) -> TokenResponse:
    iam.limit_attempts("refresh", meta)
    token = _refresh_token(body, request, settings)
    if token is None:
        raise UnauthenticatedError("No refresh token.", "token_invalid")
    return _tokens(iam.refresh(token, meta), request, response, settings)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    iam: IAM,
    meta: Meta,
    request: Request,
    settings: AppSettings,
    body: RefreshRequest | None = None,
) -> Response:
    token = _refresh_token(body, request, settings)
    if token is None and not wants_cookie(request):
        raise UnauthenticatedError("No refresh token.", "token_invalid")
    if token is not None:
        iam.logout(token, meta)
    out = Response(status_code=status.HTTP_204_NO_CONTENT)
    if wants_cookie(request):
        clear_refresh_cookie(out, settings)
    return out


@router.post("/logout-all")
def logout_all(principal: CurrentPrincipal, iam: IAM, meta: Meta) -> dict[str, int]:
    """Revoke every refresh token of the caller ("log out everywhere")."""
    return {"revoked": iam.logout_all(principal, meta)}

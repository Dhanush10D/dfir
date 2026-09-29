"""FastAPI application factory (guide 14.2)."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1 import router as api_v1_router
from app.config import Settings, get_settings
from app.core.audit_middleware import AuditMiddleware
from app.core.errors import register_handlers
from app.core.logging import get_logger, setup_logging
from app.core.middleware import RequestIdMiddleware
from app.deps import get_audit_sink

API_PREFIX = "/api/v1"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    setup_logging(settings.log_level, settings.log_json)

    app = FastAPI(
        title="dfirbench",
        version=__version__,
        openapi_url=f"{API_PREFIX}/openapi.json",
        docs_url=f"{API_PREFIX}/docs",
        redoc_url=None,
    )
    app.state.settings = settings
    # Tests replace this with a fake sink (or None to disable request auditing).
    app.state.audit_sink = get_audit_sink() if settings.audit_http_requests else None

    # Order (outermost first): request id, audit, CORS. Request id wraps everything so every
    # response (incl. errors) gets an id; audit sees the final status of every API request.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Request-ID",
            "Idempotency-Key",
            "X-Token-Delivery",
        ],
        expose_headers=[
            "X-Request-ID",
            "X-Evidence-SHA256",
            "Retry-After",
            "Content-Disposition",
            "X-Export-Rows",
            "X-Export-Truncated",
            "X-Export-SHA256",
        ],
    )
    app.add_middleware(AuditMiddleware, sink_getter=lambda: getattr(app.state, "audit_sink", None))
    app.add_middleware(RequestIdMiddleware)
    register_handlers(app)
    app.include_router(api_v1_router, prefix=API_PREFIX)

    get_logger("dfirbench").info("app_created", env=settings.app_env, version=__version__)
    return app


app = create_app()

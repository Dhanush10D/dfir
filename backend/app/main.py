"""FastAPI application factory (guide 14.2)."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1 import router as api_v1_router
from app.config import Settings, get_settings
from app.core.errors import register_handlers
from app.core.logging import get_logger, setup_logging
from app.core.middleware import RequestIdMiddleware

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

    # Order: CORS inside, request-id outermost so every response (incl. errors) gets an id.
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
        ],
        expose_headers=["X-Request-ID"],
    )
    app.add_middleware(RequestIdMiddleware)
    register_handlers(app)
    app.include_router(api_v1_router, prefix=API_PREFIX)

    get_logger("dfirbench").info("app_created", env=settings.app_env, version=__version__)
    return app


app = create_app()

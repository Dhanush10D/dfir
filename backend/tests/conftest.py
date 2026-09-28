"""Shared fixtures. Unit tests never touch Docker; DB fixtures live in tests/integration."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.deps import get_app_settings, get_readiness_checks
from app.main import create_app
from app.services.health import CheckResult


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings() -> Settings:
    # _env_file=None: ignore any developer .env so tests are hermetic.
    return Settings(_env_file=None, app_env="test", log_json=True)  # type: ignore[call-arg]


def ok_check(name: str) -> Callable[[], CheckResult]:
    return lambda: CheckResult(name=name, ok=True, latency_ms=0.1)


def failing_check(name: str, error: str = "ConnectionError") -> Callable[[], CheckResult]:
    return lambda: CheckResult(name=name, ok=False, latency_ms=0.1, error=error)


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    application = create_app(settings)
    application.dependency_overrides[get_app_settings] = lambda: settings
    application.dependency_overrides[get_readiness_checks] = lambda: [
        ok_check("database"),
        ok_check("redis"),
        ok_check("storage"),
    ]
    return application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c

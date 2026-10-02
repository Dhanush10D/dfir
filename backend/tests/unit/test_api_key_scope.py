"""Read-scoped API keys: GET and the read-only POST routes (search with a body) are allowed."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import get_iam
from app.core.permissions import Principal
from app.db.models import UserRole


class _Iam:
    def principal_from_api_key(self, key: str) -> Principal:
        return Principal(
            uuid.uuid4(), "k@x.test", "k", UserRole.analyst, "api_key", frozenset({"read"})
        )


def _status(app: FastAPI, client: TestClient, path: str, body: Any) -> tuple[int, Any]:
    app.dependency_overrides[get_iam] = lambda: _Iam()
    try:
        r = client.post(path, json=body, headers={"X-API-Key": "dfk_test"})
    except Exception as exc:  # noqa: BLE001 - past the scope check, the service has no DB here
        return 0, type(exc).__name__
    finally:
        app.dependency_overrides.pop(get_iam, None)
    return r.status_code, r.json() if r.content else None


def test_read_key_may_search_but_not_write(app: FastAPI, client: TestClient) -> None:
    case = uuid.uuid4()
    status, body = _status(app, client, f"/api/v1/cases/{case}/events/search", {"q": ""})
    assert not (status == 403 and "scope" in str(body)), body
    status, body = _status(app, client, "/api/v1/cases", {"title": "t", "severity": "low"})
    assert status == 403 and "write" in str(body), body


def test_case_update_rejects_explicit_null_for_required_columns() -> None:
    import pytest
    from pydantic import ValidationError

    from app.schemas.cases import CaseUpdate

    for field in ("title", "severity", "status"):
        with pytest.raises(ValidationError):
            CaseUpdate.model_validate({field: None})
    assert CaseUpdate.model_validate({"description": None}).model_dump(exclude_unset=True) == {
        "description": None
    }

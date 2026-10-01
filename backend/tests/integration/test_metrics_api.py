"""Phase 10: GET /metrics on the test database (token, families, failing sections)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from app.deps import get_app_settings, get_queue_inspector
from app.services.metrics import MetricsCollector
from tests.integration.harness import Harness

pytestmark = pytest.mark.integration

TOKEN = "metrics-token-for-tests-0123456789abcdef"


class FakeQueues:
    def __init__(self, broken: bool = False) -> None:
        self.broken = broken

    def llen(self, name: str) -> Any:
        if self.broken:
            raise ConnectionError("redis down")
        return {"parse": 3}.get(name, 0)


def _enable(h: Harness, token: str | None = TOKEN, queues: FakeQueues | None = None) -> None:
    secret = SecretStr(token) if token else None
    settings = h.settings.model_copy(update={"metrics_token": secret, "metrics_cache_s": 0})
    h.app.dependency_overrides[get_app_settings] = lambda: settings
    h.app.dependency_overrides[get_queue_inspector] = lambda: queues or FakeQueues()
    MetricsCollector.reset_cache()


def test_metrics_are_off_without_a_token(h: Harness) -> None:
    _enable(h, token=None)
    assert h.client.get("/metrics").status_code == 404
    assert h.client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 404


def test_metrics_need_the_token(h: Harness) -> None:
    _enable(h)
    assert h.client.get("/metrics").status_code == 401
    assert h.client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert h.client.get("/metrics", headers={"Authorization": TOKEN}).status_code == 401


def test_metrics_report_jobs_queues_and_http(h: Harness) -> None:
    _enable(h)
    admin = h.make_user()
    h.create_case(admin, "Metrics case")
    r = h.client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/plain; version=0.0.4")
    body = r.text
    for family in ("dfir_jobs", "dfir_evidence", "dfir_outbound_deliveries"):
        assert f"# TYPE {family} gauge" in body  # may have no samples on a fresh database
    for sample in (
        "dfir_http_requests_total{",
        "dfir_http_request_duration_seconds_bucket{",
        'dfir_custody_verification_failures{action="hash_failed"}',
        "dfir_ai_calls_today ",
        "dfir_events_ingested_1h ",
    ):
        assert any(line.startswith(sample) for line in body.splitlines()), sample
    assert 'dfir_queue_depth{queue="parse"} 3' in body
    assert 'route="/cases",status="2xx"' in body
    assert 'dfir_metrics_section_up{section="queues"} 1' in body
    assert "Metrics case" not in body


def test_a_failing_section_does_not_break_the_scrape(h: Harness) -> None:
    _enable(h, queues=FakeQueues(broken=True))
    r = h.client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200
    assert 'dfir_metrics_section_up{section="queues"} 0' in r.text
    assert 'dfir_metrics_section_up{section="jobs"} 1' in r.text


def test_metrics_scrapes_are_not_audited(h: Harness) -> None:
    _enable(h)
    h.client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    from sqlalchemy import text

    with h.engine.connect() as conn:
        n = conn.execute(text("SELECT count(*) FROM audit_log WHERE path = '/metrics'")).scalar()
    assert n == 0

"""Prometheus rendering and the HTTP metrics middleware (Phase 10, guide 21.4)."""

from __future__ import annotations

import re

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.metrics import (
    HTTP_LATENCY,
    HTTP_REQUESTS,
    Counter,
    Family,
    Histogram,
    MetricsMiddleware,
    escape,
    number,
    render,
)
from app.services.metrics import QUEUES

SAMPLE = re.compile(
    r'^[a-z_:][a-z0-9_:]*(\{[a-z_]+="[^"\\\n]*(?:\\.[^"\\\n]*)*"(,[a-z_]+="[^"]*")*\})? \S+$'
)


def test_numbers_and_escaping() -> None:
    assert number(3.0) == "3" and number(0.25) == "0.25"
    assert number(float("inf")) == "+Inf" and number(float("nan")) == "NaN"
    assert escape('a"b\\c\nd') == 'a\\"b\\\\c\\nd'


def test_family_renders_help_type_and_samples() -> None:
    fam = Family("dfir_x", "Help with \\ and\nnewline", "gauge")
    fam.add(2, {"k": 'v"1'})
    text = render([fam])
    assert text.startswith("# HELP dfir_x Help with \\\\ and\\nnewline\n# TYPE dfir_x gauge\n")
    assert 'dfir_x{k="v\\"1"} 2\n' in text


def test_counter_and_histogram() -> None:
    counter = Counter("c_total", "c", ("a",))
    counter.inc(("x",))
    counter.inc(("x",), 2)
    assert counter.family().samples == [("", {"a": "x"}, 3.0)]
    hist = Histogram("h_seconds", "h", ("m",), buckets=(0.1, 1.0))
    for value in (0.05, 0.5, 5.0):
        hist.observe(("GET",), value)
    samples = {(s, tuple(sorted(lbl.items()))): v for s, lbl, v in hist.family().samples}
    assert samples[("_bucket", (("le", "0.1"), ("m", "GET")))] == 1
    assert samples[("_bucket", (("le", "1"), ("m", "GET")))] == 2
    assert samples[("_bucket", (("le", "+Inf"), ("m", "GET")))] == 3
    assert samples[("_count", (("m", "GET"),))] == 3
    assert samples[("_sum", (("m", "GET"),))] == 5.55


def test_middleware_labels_use_route_templates_not_ids() -> None:
    app = FastAPI()

    @app.get("/api/v1/cases/{case_id}")
    def case(case_id: str) -> dict[str, str]:
        return {"id": case_id}

    app.add_middleware(MetricsMiddleware, prefix="/api/v1")
    client = TestClient(app)
    client.get("/api/v1/cases/very-secret-id-123")
    client.get("/api/v1/nope/also-secret")
    client.get("/elsewhere")
    text = render([HTTP_REQUESTS.family(), HTTP_LATENCY.family()])
    assert 'route="/api/v1/cases/{case_id}",status="2xx"' in text
    assert 'route="unmatched",status="4xx"' in text
    assert "secret" not in text and "elsewhere" not in text
    for line in text.splitlines():
        assert line.startswith("#") or SAMPLE.match(line), line


def test_metrics_queue_list_matches_celery() -> None:
    from app.workers.celery_app import QUEUES as CELERY_QUEUES

    assert QUEUES == CELERY_QUEUES

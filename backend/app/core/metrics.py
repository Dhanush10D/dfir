"""Prometheus metrics without a client library (guide 21.4; text exposition format 0.0.4).

The API process (one uvicorn worker) keeps HTTP counters and a latency histogram in memory;
everything else (jobs, queues, verification failures, AI usage, outbound deliveries) is read at
scrape time by ``services/metrics.py``. Labels never carry ids or user input: the HTTP path label
is the matched route template (``/cases/{case_id}``), or ``unmatched``.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from starlette.types import ASGIApp, Message, Receive, Scope, Send

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 120.0)
MetricType = Literal["counter", "gauge", "histogram"]


def escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def number(value: float) -> str:
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if float(value).is_integer() and abs(value) < 2**53:
        return str(int(value))
    return repr(float(value))


def label_text(labels: Mapping[str, str]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{escape(str(v))}"' for k, v in labels.items())
    return "{" + inner + "}"


@dataclass
class Family:
    """One metric family with its samples (suffix, labels, value)."""

    name: str
    help: str
    type: MetricType
    samples: list[tuple[str, dict[str, str], float]] = field(default_factory=list)

    def add(self, value: float, labels: Mapping[str, str] | None = None, suffix: str = "") -> None:
        self.samples.append((suffix, dict(labels or {}), float(value)))

    def render(self) -> str:
        lines = [f"# HELP {self.name} {escape(self.help)}", f"# TYPE {self.name} {self.type}"]
        for suffix, labels, value in self.samples:
            lines.append(f"{self.name}{suffix}{label_text(labels)} {number(value)}")
        return "\n".join(lines)


class Counter:
    def __init__(self, name: str, help_text: str, labelnames: Sequence[str]) -> None:
        self.name, self.help, self.labelnames = name, help_text, tuple(labelnames)
        self._values: dict[tuple[str, ...], float] = {}
        self._lock = threading.Lock()

    def inc(self, labels: Sequence[str], value: float = 1.0) -> None:
        key = tuple(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + value

    def family(self) -> Family:
        fam = Family(self.name, self.help, "counter")
        with self._lock:
            items = sorted(self._values.items())
        for key, value in items:
            fam.add(value, dict(zip(self.labelnames, key, strict=True)))
        return fam


class Histogram:
    def __init__(
        self,
        name: str,
        help_text: str,
        labelnames: Sequence[str],
        buckets: Sequence[float] = LATENCY_BUCKETS,
    ) -> None:
        self.name, self.help, self.labelnames = name, help_text, tuple(labelnames)
        self.buckets = tuple(sorted(buckets))
        self._data: dict[tuple[str, ...], tuple[list[int], float, int]] = {}
        self._lock = threading.Lock()

    def observe(self, labels: Sequence[str], value: float) -> None:
        key = tuple(labels)
        with self._lock:
            counts, total, n = self._data.get(key, ([0] * len(self.buckets), 0.0, 0))
            for i, bound in enumerate(self.buckets):
                if value <= bound:
                    counts[i] += 1
            self._data[key] = (counts, total + value, n + 1)

    def family(self) -> Family:
        fam = Family(self.name, self.help, "histogram")
        with self._lock:
            items = sorted((k, (list(c), s, n)) for k, (c, s, n) in self._data.items())
        for key, (counts, total, n) in items:
            labels = dict(zip(self.labelnames, key, strict=True))
            for bound, count in zip(self.buckets, counts, strict=True):
                fam.add(count, {**labels, "le": number(bound)}, "_bucket")
            fam.add(n, {**labels, "le": "+Inf"}, "_bucket")
            fam.add(total, labels, "_sum")
            fam.add(n, labels, "_count")
        return fam


HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
HTTP_REQUESTS = Counter(
    "dfir_http_requests_total",
    "API requests by method, route template and status class",
    ("method", "route", "status"),
)
HTTP_LATENCY = Histogram(
    "dfir_http_request_duration_seconds",
    "API request latency by method and route template",
    ("method", "route"),
)


def render(families: Iterable[Family]) -> str:
    return "\n".join(f.render() for f in families) + "\n"


class MetricsMiddleware:
    """Counts API requests (pure ASGI; the response body is not touched)."""

    def __init__(self, app: ASGIApp, prefix: str = "/api/v1") -> None:
        self.app = app
        self.prefix = prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not str(scope.get("path", "")).startswith(self.prefix):
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        status = [500]

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status[0] = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            route = scope.get("route")
            template = getattr(route, "path", None) or "unmatched"
            method = str(scope.get("method", "?")).upper()
            if method not in HTTP_METHODS:  # arbitrary tokens would grow the label set
                method = "OTHER"
            HTTP_REQUESTS.inc((method, template, f"{status[0] // 100}xx"))
            HTTP_LATENCY.observe((method, template), time.perf_counter() - started)

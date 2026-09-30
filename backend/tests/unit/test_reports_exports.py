"""STIX 2.1 bundle (validated with the OASIS stix2 library), CSV formula guard, JSON exports."""

from __future__ import annotations

import csv
import io
import json

import pytest
import stix2
from stix2patterns.validator import run_validator

from app.core.csvsafe import csv_cell
from app.reports.exports import (
    TLP_MARKINGS,
    custody_json,
    iocs_csv,
    report_json,
    stix_bundle,
    stix_json,
    stix_pattern,
    stix_ts,
    timeline_csv,
)
from tests.unit.report_fixtures import (
    sample_context,
    sample_findings,
    sample_meta,
    sample_sections,
)


def test_stix_bundle_parses_and_patterns_validate() -> None:
    bundle = stix_bundle(sample_context(), sample_meta())
    parsed = stix2.parse(json.dumps(bundle), allow_custom=False)
    types = [o.type for o in parsed.objects]
    assert types.count("indicator") == 3
    assert types.count("attack-pattern") == 1 and types[0] == "identity" and types[-1] == "report"
    for obj in bundle["objects"]:
        if obj["type"] == "indicator":
            assert run_validator(obj["pattern"]) == [], obj["pattern"]
    report = bundle["objects"][-1]
    assert set(report["object_refs"]) == {o["id"] for o in bundle["objects"][:-1]}


def test_stix_is_deterministic_and_scoped_to_the_report() -> None:
    a = stix_json(sample_context(), sample_meta())
    assert a == stix_json(sample_context(), sample_meta())
    other = stix_bundle(sample_context(), sample_meta(report_id="another"))
    ids_a = {o["id"] for o in json.loads(a)["objects"] if o["type"] == "indicator"}
    ids_b = {o["id"] for o in other["objects"] if o["type"] == "indicator"}
    assert not ids_a & ids_b


def test_stix_tlp_mapping_is_conservative() -> None:
    bundle = stix_bundle(sample_context(), sample_meta())
    by_value = {
        o["name"].split(": ", 1)[1]: o for o in bundle["objects"] if o["type"] == "indicator"
    }
    assert by_value["evil.example"]["object_marking_refs"] == [TLP_MARKINGS["amber"]]
    strict = next(v for k, v in by_value.items() if k.startswith("it's"))
    assert strict["object_marking_refs"] == [TLP_MARKINGS["red"]]
    assert bundle["objects"][-1]["object_marking_refs"] == [TLP_MARKINGS["red"]]


@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        ("ip", "198.51.100.7"),
        ("ip", "2001:db8::1"),
        ("domain", "x.example"),
        ("url", "http://x.example/a?b='c'"),
        ("md5", "a" * 32),
        ("sha1", "b" * 40),
        ("sha256", "c" * 64),
        ("email", "a@x.example"),
        ("filename", "a'] OR [file:name = 'b"),
        ("filename", "back\\slash"),
    ],
)
def test_stix_patterns_quote_hostile_values(ioc_type: str, value: str) -> None:
    pattern = stix_pattern(ioc_type, value)
    assert pattern is not None
    assert run_validator(pattern) == []
    assert pattern.count("[") == 1 or ioc_type == "filename"
    assert stix_pattern("unknown", "x") is None


def test_stix_timestamps() -> None:
    assert stix_ts("2026-09-02T07:00:00.123456Z") == "2026-09-02T07:00:00.123Z"
    assert stix_ts("2026-09-02T09:00:00+02:00") == "2026-09-02T07:00:00.000Z"
    assert stix_ts(None) == "1970-01-01T00:00:00.000Z"


def test_empty_ioc_bundle_still_valid() -> None:
    bundle = stix_bundle(sample_context(iocs=[], attack=[]), sample_meta())
    stix2.parse(json.dumps(bundle), allow_custom=False)


def test_csv_exports_neutralise_formulas() -> None:
    rows = list(csv.reader(io.StringIO(iocs_csv(sample_context()).decode())))
    assert rows[0][0] == "type"
    assert "'@SUM(1)" in rows[2]
    timeline = list(csv.reader(io.StringIO(timeline_csv(sample_context()).decode())))
    assert timeline[1][8] == '\'=HYPERLINK("http://evil")'
    for value in ("=1+1", "+1", "-1", "@x", "\tx", "\rx", " =x", chr(0xFF1D) + "x"):
        assert csv_cell(value).startswith("'"), value
    assert csv_cell("ok") == "ok"


def test_json_exports_are_deterministic_and_complete() -> None:
    args = (sample_meta(), sample_context(), sample_sections(), sample_findings())
    a = report_json(*args)
    assert a == report_json(*args)
    doc = json.loads(a)
    assert doc["schema"] == "dfirbench.report/1" and doc["findings"][0]["id"] == "f-1"
    custody = json.loads(custody_json(sample_context()))
    assert custody["custody"][0]["label"] == "EV-001"

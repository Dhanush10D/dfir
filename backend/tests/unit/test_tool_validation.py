"""The tool validation appendix (guide 22.7) matches what the parsers and rules produce now.

Regenerate with ``python scripts/tool-validation.py`` after a deliberate parser, fixture, golden or
rule change, and review the diff.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]


def _module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "tool_validation", ROOT / "scripts" / "tool-validation.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tool_validation_records_are_current() -> None:
    tv = _module()
    data = tv.build()
    committed = json.loads(tv.JSON_OUT.read_text(encoding="utf-8"))
    assert data == committed, "run `python scripts/tool-validation.py` and review the diff"
    doc = tv.DOC.read_text(encoding="utf-8")
    assert tv.render_doc(doc, tv.markdown(data)) == doc
    assert all(p["matches_golden"] for p in data["parsers"])
    assert all(r["passed"] for r in data["rules"])
    assert {p["parser"] for p in data["parsers"]} >= {"evtx", "linux_auth", "tsk_fs", "zeek"}
    assert len(data["integrity"]) >= 6

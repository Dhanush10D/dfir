"""Feature definitions (A1, A2, A3, A4, A5, A7): output schema, citation rules, extra checks,
and the pure pack builders shared by the service and the eval harness."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel

from app.ai.decode import ScriptAnalysis
from app.ai.packs import EvidencePack, PackFullError
from app.ai.runner import FeatureSpec
from app.ai.schemas import (
    AlertExplanation,
    ChatAnswer,
    Narrative,
    NlqOutput,
    ReportDraft,
    ScriptExplanation,
)
from app.search.language import QueryError, parse

MAX_SCRIPT_CHARS = 12_000  # of the script shown to the model (S1); decoded layers likewise
MAX_LAYERS_IN_PACK = 8


def check_query(obj: BaseModel) -> list[str]:
    """A1: the generated query must parse with our own search grammar (never SQL)."""
    query = getattr(obj, "query", None)
    if query is None:
        return []
    try:
        parse(query)
    except QueryError as exc:
        return [f"query does not parse at character {exc.position}: {exc.message}"]
    return []


SPECS: dict[str, FeatureSpec] = {
    "nlq": FeatureSpec("nlq", NlqOutput, extra_check=check_query),
    "alert_explain": FeatureSpec(
        "alert_explain", AlertExplanation, required_cites=("key_facts", "attack_candidates")
    ),
    "narrative": FeatureSpec("narrative", Narrative, required_cites=("timeline",)),
    "chat": FeatureSpec("chat", ChatAnswer, required_cites=("key_facts",)),
    "script_explain": FeatureSpec(
        "script_explain",
        ScriptExplanation,
        required_cites=("behaviors", "attack_candidates", "indicators"),
        indicator_lists=("indicators",),
    ),
    "report_draft": FeatureSpec("report_draft", ReportDraft, required_cites=("claims",)),
}


def alert_pack(
    alert: Mapping[str, Any],
    events: Iterable[Mapping[str, Any]],
    *,
    max_records: int,
    max_field_chars: int,
) -> EvidencePack:
    pack = EvidencePack(max_records=max_records, max_field_chars=max_field_chars)
    pack.add_alert(alert)
    for ev in events:
        try:
            pack.add_event(ev)
        except PackFullError:
            break
    return pack


def narrative_pack(
    alerts: Iterable[Mapping[str, Any]],
    events: Iterable[Mapping[str, Any]],
    *,
    max_records: int,
    max_field_chars: int,
) -> EvidencePack:
    pack = EvidencePack(max_records=max_records, max_field_chars=max_field_chars)
    try:
        for al in alerts:
            pack.add_alert(al)
        for ev in events:
            pack.add_event(ev)
    except PackFullError:
        pass
    return pack


def events_pack(
    events: Iterable[Mapping[str, Any]], *, max_records: int, max_field_chars: int
) -> EvidencePack:
    pack = EvidencePack(max_records=max_records, max_field_chars=max_field_chars)
    for ev in events:
        try:
            pack.add_event(ev)
        except PackFullError:
            break
    return pack


def script_pack(
    text: str,
    analysis: ScriptAnalysis,
    *,
    event: Mapping[str, Any] | None,
    max_field_chars: int,
) -> EvidencePack:
    """S1 = the input, D1.. = decoded layers (by the deterministic decoder), E1 = source event."""
    pack = EvidencePack(max_records=MAX_LAYERS_IN_PACK + 2, max_field_chars=max_field_chars)
    pack.add_text("script", text, max_chars=MAX_SCRIPT_CHARS, label="script")
    for layer in analysis.layers[1 : MAX_LAYERS_IN_PACK + 1]:
        pack.add_text(
            "decoded",
            layer.text,
            max_chars=MAX_SCRIPT_CHARS,
            label=f"decoded layer={layer.index} from={layer.parent} method={layer.method}",
        )
    if event is not None:
        pack.add_event(event)
    return pack

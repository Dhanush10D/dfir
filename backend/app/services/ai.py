"""AiService (guide 13): the five AI features, provenance, review and per-case policy.

Every feature follows the same path: case access (404 across cases) + ``ai:use`` + open case +
AI enabled for the case + daily budget -> context from THIS case only -> evidence pack ->
:class:`~app.ai.runner.FeatureRunner` (gateway, validators, one corrective retry) -> server-side
re-check that every cited record exists in the same case -> ``ai_interactions`` row + audit row.

AI output is a suggestion: nothing here writes alerts, evidence, custody, notes or verdicts. A
human accepts or rejects a *valid* interaction once (row lock + re-check; a DB trigger enforces the
same rule for direct SQL), with an audit record.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai.decode import analyze
from app.ai.features import (
    SPECS,
    alert_pack,
    events_pack,
    narrative_pack,
    script_pack,
)
from app.ai.gateway import Gateway
from app.ai.llm import AiDisabledForCaseError, AiProviderError, AiRateLimitedError
from app.ai.packs import EvidencePack
from app.ai.prompts import TEMPLATES, prompt_versions
from app.ai.runner import FeatureRunner, RunOutcome
from app.config import Settings
from app.core.exceptions import AppError, ConflictError, InvalidStateError, NotFoundError
from app.core.permissions import Permission, Principal
from app.db.models import (
    AiInteraction,
    Alert,
    AlertEvent,
    AlertStatus,
    Case,
    CaseStatus,
    Event,
)
from app.services.ai_index import AiIndexService, IndexInfo, event_columns, row_map
from app.services.audit import AuditService, RequestMeta
from app.services.authz import CaseAccess, load_case_access, require_global

MAX_LIST = 200
NARRATIVE_MAX_ALERTS = 30
ALERT_MAX_EVENTS = 100
BLOCKING_WARNINGS = frozenset({"injection_suspected", "unsupported_claim"})


@dataclass
class FeatureResult:
    interaction: AiInteraction
    outcome: RunOutcome
    citations: dict[str, dict[str, Any]]
    extras: dict[str, Any] = field(default_factory=dict)


def _alert_map(a: Alert) -> dict[str, Any]:
    return {
        "id": a.id,
        "rule_id": a.rule_id,
        "severity": a.severity.value,
        "status": a.status.value,
        "host": a.host,
        "user": a.user,
        "attack_tags": list(a.attack_tags or []),
        "first_seen": a.first_seen,
        "last_seen": a.last_seen,
        "event_count": a.event_count,
        "title": a.title,
    }


class AiService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        gateway_factory: Callable[[], Gateway],
    ) -> None:
        self.session = session
        self.settings = settings
        self.gateway_factory = gateway_factory
        self.audit = AuditService(session)
        self._gateway: Gateway | None = None

    # ------------------------------------------------------------------ plumbing

    @property
    def gateway(self) -> Gateway:
        if self._gateway is None:
            self._gateway = self.gateway_factory()
        return self._gateway

    def _access(self, principal: Principal, case_id: uuid.UUID) -> CaseAccess:
        return load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )

    def _prepare(self, principal: Principal, case_id: uuid.UUID) -> CaseAccess:
        access = self._access(principal, case_id)
        access.require(Permission.AI_USE)
        if access.case.status is CaseStatus.closed:
            raise InvalidStateError("The case is closed.")
        if not access.case.ai_enabled:
            raise AiDisabledForCaseError()
        self.gateway.check_available()
        self._check_budget()
        return access

    def _check_budget(self) -> None:
        now = datetime.now(UTC)
        day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        tokens, cost = self.session.execute(
            select(
                func.coalesce(
                    func.sum(
                        func.coalesce(AiInteraction.input_tokens, 0)
                        + func.coalesce(AiInteraction.output_tokens, 0)
                    ),
                    0,
                ),
                func.coalesce(func.sum(AiInteraction.cost_usd), 0),
            ).where(AiInteraction.created_at >= day)
        ).one()
        retry = int((day + timedelta(days=1) - now).total_seconds()) + 1
        if int(tokens) >= self.settings.ai_daily_token_budget:
            raise AiRateLimitedError("The daily AI token budget is used up.", retry)
        if self._priced() and Decimal(cost or 0) >= Decimal(str(self.settings.ai_daily_budget_usd)):
            raise AiRateLimitedError("The daily AI cost budget is used up.", retry)

    def _priced(self) -> bool:
        s = self.settings
        return s.llm_price_input_per_mtok is not None and s.llm_price_output_per_mtok is not None

    def _cost(self, outcome: RunOutcome) -> Decimal | None:
        if not self._priced():
            return None
        s = self.settings
        usd = (
            outcome.input_tokens * (s.llm_price_input_per_mtok or 0)
            + outcome.output_tokens * (s.llm_price_output_per_mtok or 0)
        ) / 1_000_000
        return Decimal(str(round(usd, 4)))

    def _runner(self) -> FeatureRunner:
        return FeatureRunner(
            self.gateway,
            redaction_policy=self.settings.ai_redaction_policy,
            redact_local=self.settings.ai_redact_local,
            max_tokens=self.settings.ai_max_tokens,
        )

    def _missing_refs(self, case_id: uuid.UUID, refs: Iterable[Mapping[str, Any]]) -> list[str]:
        """Short ids whose event/alert does not exist in ``case_id`` (server-side check)."""
        by_kind: dict[str, dict[uuid.UUID, str]] = {"event": {}, "alert": {}}
        for ref in refs:
            kind, rid = ref.get("kind"), ref.get("id")
            if kind in by_kind and rid:
                by_kind[kind][uuid.UUID(str(rid))] = str(ref.get("short_id"))
        found: set[uuid.UUID] = set()
        if by_kind["event"]:
            found |= set(
                self.session.execute(
                    select(Event.id).where(
                        Event.case_id == case_id, Event.id.in_(list(by_kind["event"]))
                    )
                ).scalars()
            )
        if by_kind["alert"]:
            found |= set(
                self.session.execute(
                    select(Alert.id).where(
                        Alert.case_id == case_id, Alert.id.in_(list(by_kind["alert"]))
                    )
                ).scalars()
            )
        missing = [sid for ids in by_kind.values() for rid, sid in ids.items() if rid not in found]
        return sorted(missing)

    def _run(
        self,
        feature: str,
        principal: Principal,
        case_id: uuid.UUID,
        pack: EvidencePack | None,
        meta: RequestMeta,
        *,
        question: str | None = None,
        context: dict[str, str] | None = None,
        input_extra: dict[str, Any] | None = None,
    ) -> FeatureResult:
        started = datetime.now(UTC)
        runner = self._runner()
        self.session.commit()  # no transaction (or row locks) held across the model call
        try:
            outcome = runner.run(
                SPECS[feature],
                pack,
                user_key=str(principal.user_id),
                case_key=str(case_id),
                question=question,
                context=context,
            )
        except AiProviderError as exc:
            row = self._record_error(feature, principal, case_id, pack, started, exc, meta)
            raise AiProviderError(exc.message, interaction_id=str(row.id)) from exc

        citations: dict[str, dict[str, Any]] = {}
        if pack is not None and outcome.citations is not None:
            for sid in outcome.citations.cited:
                rec = pack.ref_of(sid)
                if rec is not None:
                    citations[sid] = {
                        "short_id": sid,
                        "kind": rec.kind,
                        "id": rec.ref_id,
                        "ts": rec.ts,
                        "summary": rec.summary(),
                    }
        if outcome.status == "valid":
            missing = self._missing_refs(case_id, citations.values())
            if missing:
                outcome.status = "invalid"
                outcome.problems = [
                    "cited records do not exist in this case: " + ", ".join(missing)
                ]
        citations_valid = (
            None if outcome.citations is None or feature == "nlq" else outcome.citations.valid
        )
        refs = pack.input_refs() if pack is not None else {}
        row = AiInteraction(
            case_id=case_id,
            user_id=principal.user_id,
            feature=feature,
            provider=self.gateway.provider_name,
            model=outcome.model_requested,
            model_served=outcome.response.model if outcome.response else None,
            prompt_version=outcome.prompt_version,
            input_refs={"records": refs, **(input_extra or {})},
            redactions={
                "policy": outcome.redactions.get("policy"),
                "counts": outcome.redactions.get("counts", {}),
                "mapping": outcome.redactions.get("mapping", {}),
            },
            output=outcome.output,
            citations=list(citations.values()),
            citations_valid=citations_valid,
            input_tokens=outcome.input_tokens,
            output_tokens=outcome.output_tokens,
            latency_ms=outcome.latency_ms,
            cost_usd=self._cost(outcome),
            status=outcome.status,
            prompt_sha256=outcome.prompt_sha256,
            input_sha256=outcome.input_sha256,
            output_sha256=outcome.output_sha256,
            prompt_text=outcome.prompt_text,
            warnings=outcome.warnings,
            error="; ".join(outcome.problems)[:2000] or None,
            started_at=started,
        )
        self.session.add(row)
        self.session.flush()
        self.audit.record(
            f"ai.{feature}",
            user_id=principal.user_id,
            meta=meta,
            object_type="ai_interaction",
            object_id=row.id,
            detail={
                "case_id": str(case_id),
                "status": outcome.status,
                "provider": row.provider,
                "model": row.model,
                "prompt_version": row.prompt_version,
                "input_sha256": row.input_sha256,
                "warnings": sorted({str(w.get("type")) for w in outcome.warnings}),
            },
        )
        self.session.commit()
        self.session.refresh(row)
        return FeatureResult(row, outcome, citations)

    def _record_error(
        self,
        feature: str,
        principal: Principal,
        case_id: uuid.UUID,
        pack: EvidencePack | None,
        started: datetime,
        exc: AppError,
        meta: RequestMeta,
    ) -> AiInteraction:
        self.session.rollback()
        row = AiInteraction(
            case_id=case_id,
            user_id=principal.user_id,
            feature=feature,
            provider=self.gateway.provider_name,
            model=self.gateway.model_for(TEMPLATES[feature].tier),
            prompt_version=TEMPLATES[feature].prompt_version,
            input_refs={"records": pack.input_refs() if pack is not None else {}},
            output={},
            status="error",
            error=exc.message[:2000],
            started_at=started,
            warnings=list(pack.warnings) if pack is not None else [],
        )
        self.session.add(row)
        self.session.flush()
        self.audit.record(
            f"ai.{feature}",
            user_id=principal.user_id,
            meta=meta,
            object_type="ai_interaction",
            object_id=row.id,
            detail={"case_id": str(case_id), "status": "error", "provider": row.provider},
        )
        self.session.commit()
        return row

    # ------------------------------------------------------------------ status

    def status(self) -> dict[str, Any]:
        s = self.settings
        return {
            "enabled": s.enable_ai,
            "provider": s.llm_provider,
            "local_only": s.ai_local_only,
            "configured": s.llm_provider in ("fake",)
            or (s.llm_provider == "anthropic" and s.llm_api_key is not None)
            or (s.llm_provider in ("ollama", "openai_compat") and bool(s.llm_base_url)),
            "models": {"fast": s.llm_model_fast, "strong": s.llm_model_strong},
            "embedding_model": s.embedding_model,
            "redaction_policy": s.ai_redaction_policy,
            "prompt_versions": prompt_versions(),
        }

    # ------------------------------------------------------------------ A1 NL search

    def nlq(
        self, principal: Principal, case_id: uuid.UUID, question: str, meta: RequestMeta
    ) -> FeatureResult:
        self._prepare(principal, case_id)
        result = self._run("nlq", principal, case_id, None, meta, question=question)
        query = result.outcome.output.get("query") if result.outcome.status == "valid" else None
        result.extras = {"query_valid": result.outcome.status == "valid", "query": query}
        return result

    # ------------------------------------------------------------------ A2 alert explanation

    def explain_alert(
        self, principal: Principal, alert_id: uuid.UUID, meta: RequestMeta
    ) -> FeatureResult:
        alert = self.session.get(Alert, alert_id)
        if alert is None:
            raise NotFoundError("Alert not found.")
        try:
            self._prepare(principal, alert.case_id)
        except NotFoundError as exc:
            raise NotFoundError("Alert not found.") from exc
        limit = min(ALERT_MAX_EVENTS, self.settings.ai_max_pack_records - 1)
        rows = self.session.execute(
            select(*event_columns())
            .join(AlertEvent, (AlertEvent.event_id == Event.id) & (AlertEvent.event_ts == Event.ts))
            .where(AlertEvent.alert_id == alert_id, Event.case_id == alert.case_id)
            .order_by(Event.ts, Event.id)
            .limit(limit)
        ).all()
        pack = alert_pack(
            _alert_map(alert),
            [row_map(r) for r in rows],
            max_records=self.settings.ai_max_pack_records,
            max_field_chars=self.settings.ai_max_field_chars,
        )
        return self._run(
            "alert_explain",
            principal,
            alert.case_id,
            pack,
            meta,
            input_extra={"alert_id": str(alert_id)},
        )

    # ------------------------------------------------------------------ A3 narrative

    def narrative(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        meta: RequestMeta,
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        host: str | None = None,
    ) -> FeatureResult:
        self._prepare(principal, case_id)
        if start is not None and end is not None and start > end:
            raise AppError("invalid_range", "'start' must be before 'end'.", 422)
        conds = [
            Alert.case_id == case_id,
            Alert.status != AlertStatus.false_positive,
            Alert.stale.is_(False),
        ]
        if host:
            conds.append(func.lower(Alert.host) == host.lower())
        if start is not None:
            conds.append(Alert.last_seen >= start)
        if end is not None:
            conds.append(Alert.first_seen <= end)
        alerts = list(
            self.session.execute(
                select(Alert)
                .where(*conds)
                .order_by(Alert.risk_score.desc(), Alert.first_seen)
                .limit(NARRATIVE_MAX_ALERTS)
            ).scalars()
        )
        budget = max(self.settings.ai_max_pack_records - len(alerts), 1)
        ev_conds = [Event.case_id == case_id]
        if start is not None:
            ev_conds.append(Event.ts >= start)
        if end is not None:
            ev_conds.append(Event.ts <= end)
        if host:
            ev_conds.append(func.lower(Event.host) == host.lower())
        stmt = select(*event_columns()).where(*ev_conds)
        if alerts:  # key events = events linked to the alerts
            linked = select(AlertEvent.event_id).where(
                AlertEvent.alert_id.in_([a.id for a in alerts])
            )
            stmt = stmt.where(Event.id.in_(linked))
        rows = self.session.execute(stmt.order_by(Event.ts, Event.id).limit(budget)).all()
        alerts.sort(key=lambda a: a.first_seen)
        pack = narrative_pack(
            [_alert_map(a) for a in alerts],
            [row_map(r) for r in rows],
            max_records=self.settings.ai_max_pack_records,
            max_field_chars=self.settings.ai_max_field_chars,
        )
        context = {
            "start": start.isoformat() if start else "(case start)",
            "end": end.isoformat() if end else "(case end)",
            "host": host or "(all hosts)",
            "selection": "events linked to alerts" if alerts else "earliest events (no alerts)",
        }
        return self._run(
            "narrative", principal, case_id, pack, meta, context=context, input_extra=context
        )

    # ------------------------------------------------------------------ A5 chat (RAG)

    def index_service(self) -> AiIndexService:
        remote = None
        if self.settings.embedding_provider != "hashing":
            remote = self.gateway.embed
        return AiIndexService(self.session, self.settings, remote_embed=remote)

    def index_info(self, principal: Principal, case_id: uuid.UUID) -> IndexInfo:
        self._access(principal, case_id)
        info = self.index_service().info(case_id)
        self.session.commit()
        return info

    def rebuild_index(
        self, principal: Principal, case_id: uuid.UUID, meta: RequestMeta
    ) -> IndexInfo:
        self._prepare(principal, case_id)
        info = self.index_service().rebuild(case_id)
        self.audit.record(
            "ai.index_rebuilt",
            user_id=principal.user_id,
            meta=meta,
            object_type="case",
            object_id=case_id,
            detail={"chunks": info.chunk_count, "events": info.event_count},
        )
        self.session.commit()
        return info

    def chat(
        self, principal: Principal, case_id: uuid.UUID, question: str, meta: RequestMeta
    ) -> FeatureResult:
        self._prepare(principal, case_id)
        index = self.index_service()
        info = index.ensure_fresh(case_id)
        chunks = index.retrieve(case_id, question, top_k=self.settings.ai_chat_top_k)
        events = index.events_for(case_id, chunks, limit=self.settings.ai_chat_max_events)
        pack = events_pack(
            events,
            max_records=self.settings.ai_max_pack_records,
            max_field_chars=self.settings.ai_max_field_chars,
        )
        result = self._run(
            "chat",
            principal,
            case_id,
            pack,
            meta,
            question=question,
            input_extra={"chunks": [str(c.id) for c in chunks]},
        )
        if info.truncated:
            result.outcome.warnings.append(
                {"type": "index_truncated", "limit": self.settings.ai_index_max_events}
            )
        result.extras = {"index": info.as_dict()}
        return result

    # ------------------------------------------------------------------ A7 script explanation

    def explain_script(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        meta: RequestMeta,
        *,
        text: str | None = None,
        event_id: uuid.UUID | None = None,
    ) -> FeatureResult:
        self._prepare(principal, case_id)
        event: dict[str, Any] | None = None
        if event_id is not None:
            row = self.session.execute(
                select(*event_columns()).where(Event.case_id == case_id, Event.id == event_id)
            ).one_or_none()
            if row is None:
                raise NotFoundError("Event not found.")
            event = row_map(row)
            text = event.get("cmdline") or event.get("message") or ""
        if not text or not text.strip():
            raise AppError("empty_script", "There is no script or command text to explain.", 422)
        analysis = analyze(text)
        pack = script_pack(
            text, analysis, event=event, max_field_chars=self.settings.ai_max_field_chars
        )
        result = self._run(
            "script_explain",
            principal,
            case_id,
            pack,
            meta,
            input_extra={"event_id": str(event_id) if event_id else None},
        )
        extras = analysis.to_dict()
        for layer in extras["layers"]:
            if len(layer["text"]) > 20_000:
                layer["text"] = layer["text"][:20_000] + "…[truncated]"
        result.extras = {"analysis": extras}
        return result

    # ------------------------------------------------------------------ interactions

    def _load(self, principal: Principal, iid: uuid.UUID) -> tuple[AiInteraction, CaseAccess]:
        row = self.session.get(AiInteraction, iid)
        if row is None or row.case_id is None:
            raise NotFoundError("AI interaction not found.")
        try:
            access = self._access(principal, row.case_id)
        except NotFoundError as exc:
            raise NotFoundError("AI interaction not found.") from exc
        return row, access

    def list_interactions(
        self,
        principal: Principal,
        *,
        case_id: uuid.UUID | None,
        feature: str | None,
        limit: int,
        offset: int,
    ) -> tuple[list[AiInteraction], int]:
        conds = []
        if case_id is not None:
            self._access(principal, case_id)
            conds.append(AiInteraction.case_id == case_id)
        else:
            require_global(principal, Permission.AUDIT_VIEW)  # all cases: the AI audit view
        if feature:
            conds.append(AiInteraction.feature == feature)
        if not 1 <= limit <= MAX_LIST or offset < 0:
            raise AppError("invalid_filter", f"'limit' must be 1-{MAX_LIST}.", 422)
        total = self.session.execute(
            select(func.count()).select_from(AiInteraction).where(*conds)
        ).scalar_one()
        rows = list(
            self.session.execute(
                select(AiInteraction)
                .where(*conds)
                .order_by(AiInteraction.created_at.desc(), AiInteraction.id)
                .limit(limit)
                .offset(offset)
            ).scalars()
        )
        self.session.commit()
        return rows, int(total)

    def get_interaction(self, principal: Principal, iid: uuid.UUID) -> AiInteraction:
        row, _ = self._load(principal, iid)
        self.session.commit()
        return row

    def review(
        self,
        principal: Principal,
        iid: uuid.UUID,
        meta: RequestMeta,
        *,
        decision: Literal["accept", "reject"],
        note: str | None = None,
        acknowledge_warnings: bool = False,
    ) -> AiInteraction:
        row, access = self._load(principal, iid)
        access.require(Permission.AI_USE)
        case_id = row.case_id
        if case_id is None:  # pragma: no cover - _load guarantees it
            raise NotFoundError("AI interaction not found.")
        case_status = self.session.execute(
            select(Case.status).where(Case.id == case_id).with_for_update(read=True)
        ).scalar_one()
        if case_status is CaseStatus.closed:
            self.session.rollback()
            raise InvalidStateError("The case is closed.")
        locked = self.session.execute(
            select(AiInteraction)
            .where(AiInteraction.id == iid)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()
        # Re-checked under the lock: a concurrent review may have won.
        if locked.accepted is not None:
            self.session.rollback()
            raise ConflictError(
                "This AI output was already reviewed.",
                "already_reviewed",
                accepted=locked.accepted,
            )
        if locked.status != "valid":
            self.session.rollback()
            raise InvalidStateError(
                "Only validated AI output (schema and citations) can be reviewed.",
                status=locked.status,
            )
        warn_types = {str(w.get("type")) for w in locked.warnings or []}
        if decision == "accept":
            blocking = sorted(warn_types & BLOCKING_WARNINGS)
            if blocking and not acknowledge_warnings:
                self.session.rollback()
                raise ConflictError(
                    "This output carries warnings; acknowledge them to accept it.",
                    "warnings_not_acknowledged",
                    warnings=blocking,
                )
            missing = self._missing_refs(case_id, locked.citations or [])
            if missing:
                self.session.rollback()
                raise ConflictError(
                    "Cited records no longer exist in this case.",
                    "citations_stale",
                    missing=missing,
                )
        now = datetime.now(UTC)
        locked.accepted = decision == "accept"
        locked.reviewed_by = principal.user_id
        locked.reviewed_at = now
        locked.review_note = note
        self.audit.record(
            "ai.accepted" if decision == "accept" else "ai.rejected",
            user_id=principal.user_id,
            meta=meta,
            object_type="ai_interaction",
            object_id=iid,
            detail={
                "case_id": str(case_id),
                "feature": locked.feature,
                "note": note,
                "warnings_acknowledged": sorted(warn_types & BLOCKING_WARNINGS)
                if acknowledge_warnings
                else [],
            },
        )
        self.session.commit()
        self.session.refresh(locked)
        return locked

    def feedback(
        self, principal: Principal, iid: uuid.UUID, value: int, meta: RequestMeta
    ) -> AiInteraction:
        row, access = self._load(principal, iid)
        access.require(Permission.AI_USE)
        row.feedback = value
        self.audit.record(
            "ai.feedback",
            user_id=principal.user_id,
            meta=meta,
            object_type="ai_interaction",
            object_id=iid,
            detail={"case_id": str(row.case_id), "value": value},
        )
        self.session.commit()
        self.session.refresh(row)
        return row

    def set_case_ai(
        self, principal: Principal, case_id: uuid.UUID, enabled: bool, meta: RequestMeta
    ) -> Case:
        access = load_case_access(
            self.session,
            principal,
            case_id,
            auditor_all_cases=self.settings.auditor_all_cases,
            lock=True,
        )
        access.require(Permission.CASE_MANAGE)
        case = access.case
        before = case.ai_enabled
        case.ai_enabled = enabled
        self.audit.record(
            "case.ai_settings",
            user_id=principal.user_id,
            meta=meta,
            object_type="case",
            object_id=case_id,
            detail={"ai_enabled": {"from": before, "to": enabled}},
        )
        self.session.commit()
        self.session.refresh(case)
        return case

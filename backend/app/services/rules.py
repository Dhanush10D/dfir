"""RuleService: built-in pack sync, custom rules, Sigma import, rule tests, coverage (guide 11).

Rules are global (not per case). Writes need the global ``rules:manage`` permission (lead,
admin). Every stored version is appended to ``rule_versions`` (append-only) and audited. Updates
lock the rule row (``FOR UPDATE``) and re-check the version the caller saw, so two editors can
never silently overwrite each other. Built-in rules can be enabled/disabled but not edited.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from app.core.exceptions import AppError, ConflictError, InvalidStateError, NotFoundError
from app.core.permissions import Permission, Principal
from app.db.models import Rule, RuleVersion
from app.detection import sigma
from app.detection.coverage import RuleInfo, builtin_texts, coverage_rows
from app.detection.engine import DetectionEngine
from app.detection.rules import CompiledRule, RuleError, load_rule
from app.services.audit import AuditService, RequestMeta
from app.services.authz import require_global

log = structlog.stdlib.get_logger("dfirbench.rules")

SYNC_LOCK = int.from_bytes(hashlib.sha256(b"dfir_rules_sync").digest()[:8], "big", signed=True)
MAX_TEST_EVENTS = 500


def _invalid(exc: RuleError) -> AppError:
    return AppError("invalid_rule", str(exc), 422, details={"errors": exc.errors[:50]})


def definition_of(rule: CompiledRule) -> dict[str, Any]:
    return rule.model.model_dump(mode="json")


@dataclass
class LoadedRules:
    rules: list[CompiledRule]
    warnings: list[str]


class RuleService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.audit = AuditService(session)

    # ------------------------------------------------------------------ built-in pack

    def sync_builtin(self) -> dict[str, int]:
        """Upsert the shipped pack; bump the version when a file changed. Idempotent; commits.

        Runs under a transaction-scoped advisory lock so concurrent workers/API calls serialize.
        Built-in rules no longer shipped are disabled (never deleted: alerts reference them).
        """
        counts = {"created": 0, "updated": 0, "unchanged": 0, "retired": 0}
        self.session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": SYNC_LOCK})
        texts = builtin_texts()
        for raw in texts.values():
            rule = load_rule(raw)
            row = self.session.execute(
                select(Rule).where(Rule.id == rule.id).with_for_update()
            ).scalar_one_or_none()
            if row is None:
                self._insert(rule, origin="builtin", user_id=None)
                counts["created"] += 1
            elif row.origin != "builtin":
                log.warning("builtin_rule_id_taken", rule_id=rule.id, origin=row.origin)
            elif row.sha256 != rule.sha256:
                self._new_version(row, rule, user_id=None)
                counts["updated"] += 1
            else:
                counts["unchanged"] += 1
        retired = self.session.execute(
            update(Rule)
            .where(Rule.origin == "builtin", Rule.id.not_in(list(texts)), Rule.enabled.is_(True))
            .values(enabled=False)
            .returning(Rule.id)
        ).all()
        counts["retired"] = len(retired)
        self.session.commit()
        return counts

    def _values(self, rule: CompiledRule) -> dict[str, Any]:
        return {
            "title": rule.title,
            "description": rule.model.description,
            "level": rule.level,
            "attack": list(rule.attack),
            "logsource": rule.model.logsource.model_dump(mode="json", exclude_none=True),
            "definition": definition_of(rule),
            "raw_yaml": rule.raw_yaml,
            "status": rule.status,
            "kind": rule.kind,
            "confidence": rule.confidence,
            "sha256": rule.sha256,
        }

    def _insert(
        self,
        rule: CompiledRule,
        *,
        origin: str,
        user_id: Any,
        source_text: str | None = None,
        enabled: bool = True,
    ) -> Rule:
        row = Rule(
            id=rule.id, origin=origin, version=1, enabled=enabled, created_by=user_id,
            **self._values(rule),
        )  # fmt: skip
        self.session.add(row)
        self.session.flush()
        self.session.add(
            RuleVersion(
                rule_id=rule.id,
                version=1,
                sha256=rule.sha256,
                raw_yaml=rule.raw_yaml,
                source_text=source_text,
                created_by=user_id,
            )
        )
        return row

    def _new_version(self, row: Rule, rule: CompiledRule, *, user_id: Any) -> None:
        row.version += 1
        for key, value in self._values(rule).items():
            setattr(row, key, value)
        row.updated_at = datetime.now(row.updated_at.tzinfo)
        self.session.add(
            RuleVersion(
                rule_id=row.id,
                version=row.version,
                sha256=rule.sha256,
                raw_yaml=rule.raw_yaml,
                created_by=user_id,
            )
        )

    # ------------------------------------------------------------------ read

    def list_rules(
        self,
        *,
        origin: str | None = None,
        enabled: bool | None = None,
        technique: str | None = None,
    ) -> list[Rule]:
        stmt = select(Rule)
        if origin:
            stmt = stmt.where(Rule.origin == origin)
        if enabled is not None:
            stmt = stmt.where(Rule.enabled.is_(enabled))
        if technique:
            stmt = stmt.where(Rule.attack.any(technique))  # type: ignore[arg-type]
        rows = list(self.session.execute(stmt.order_by(Rule.id)).scalars())
        self.session.commit()
        return rows

    def get(self, rule_id: str) -> tuple[Rule, list[RuleVersion]]:
        row = self.session.get(Rule, rule_id)
        if row is None:
            raise NotFoundError("Rule not found.")
        versions = list(
            self.session.execute(
                select(RuleVersion)
                .where(RuleVersion.rule_id == rule_id)
                .order_by(RuleVersion.version.desc())
            ).scalars()
        )
        self.session.commit()
        return row, versions

    def coverage(self) -> list[dict[str, object]]:
        rows = self.session.execute(
            select(Rule.id, Rule.title, Rule.level, Rule.kind, Rule.attack, Rule.enabled)
        ).all()
        self.session.commit()
        return coverage_rows(
            RuleInfo(r.id, r.title, str(r.level), r.kind, tuple(r.attack), r.enabled) for r in rows
        )

    def load_enabled(self, rule_ids: Sequence[str] | None = None) -> LoadedRules:
        """Compile the enabled rules (optionally a subset) for a detection run."""
        stmt = select(Rule).where(Rule.enabled.is_(True))
        if rule_ids:
            stmt = stmt.where(Rule.id.in_(list(rule_ids)))
        rules: list[CompiledRule] = []
        warnings: list[str] = []
        for row in self.session.execute(stmt.order_by(Rule.id)).scalars():
            try:
                compiled = load_rule(row.raw_yaml)
            except RuleError as exc:  # stored before a validator change; skip, never crash
                warnings.append(f"{row.id}: {exc}")
                continue
            if compiled.id != row.id:
                warnings.append(f"{row.id}: stored YAML declares id {compiled.id}")
                continue
            rules.append(compiled.with_version(row.version))
        self.session.commit()
        return LoadedRules(rules, warnings)

    # ------------------------------------------------------------------ write

    def create(
        self,
        principal: Principal,
        yaml_text: str,
        meta: RequestMeta,
        *,
        enabled: bool = True,
        origin: str = "custom",
        source_text: str | None = None,
        audit_action: str = "rule.created",
        notes: list[str] | None = None,
    ) -> Rule:
        require_global(principal, Permission.RULES_MANAGE)
        try:
            rule = load_rule(yaml_text)
        except RuleError as exc:
            raise _invalid(exc) from exc
        if rule.id.startswith(("DFIR-",)) and rule.id in builtin_texts():
            raise ConflictError("That id belongs to a built-in rule.", "rule_exists", id=rule.id)
        self.session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": SYNC_LOCK})
        if self.session.get(Rule, rule.id) is not None:
            self.session.rollback()
            raise ConflictError("A rule with this id already exists.", "rule_exists", id=rule.id)
        row = self._insert(
            rule, origin=origin, user_id=principal.user_id, source_text=source_text, enabled=enabled
        )
        detail: dict[str, Any] = {"version": 1, "sha256": rule.sha256, "origin": origin}
        if notes:
            detail["notes"] = notes
        self.audit.record(
            audit_action,
            user_id=principal.user_id,
            meta=meta,
            object_type="rule",
            object_id=rule.id,
            detail=detail,
        )
        self.session.commit()
        return row

    def import_sigma(
        self,
        principal: Principal,
        sigma_text: str,
        meta: RequestMeta,
        *,
        rule_id: str | None = None,
        enabled: bool = True,
    ) -> tuple[Rule, list[str]]:
        require_global(principal, Permission.RULES_MANAGE)
        try:
            _, native, notes = sigma.convert(sigma_text, rule_id)
        except sigma.SigmaError as exc:
            raise AppError(
                "unsupported_sigma", str(exc), 422, details={"unsupported": exc.errors[:50]}
            ) from exc
        row = self.create(
            principal,
            native,
            meta,
            enabled=enabled,
            origin="sigma",
            source_text=sigma_text,
            audit_action="rule.imported",
            notes=notes,
        )
        return row, notes

    def update(
        self,
        principal: Principal,
        rule_id: str,
        meta: RequestMeta,
        *,
        enabled: bool | None = None,
        yaml_text: str | None = None,
        expected_version: int | None = None,
    ) -> Rule:
        require_global(principal, Permission.RULES_MANAGE)
        if enabled is None and yaml_text is None:
            raise AppError("nothing_to_update", "Give 'enabled' and/or 'yaml'.", 422)
        row = self.session.execute(
            select(Rule).where(Rule.id == rule_id).with_for_update()
        ).scalar_one_or_none()
        if row is None:
            self.session.rollback()
            raise NotFoundError("Rule not found.")
        # Re-checked under the row lock: a concurrent editor's version is never overwritten.
        if expected_version is not None and row.version != expected_version:
            self.session.rollback()
            raise ConflictError(
                "The rule changed since you read it.", "stale_version", current=row.version
            )
        detail: dict[str, Any] = {}
        if yaml_text is not None:
            if row.origin == "builtin":
                self.session.rollback()
                raise InvalidStateError("Built-in rules cannot be edited; disable it instead.")
            try:
                rule = load_rule(yaml_text)
            except RuleError as exc:
                self.session.rollback()
                raise _invalid(exc) from exc
            if rule.id != row.id:
                self.session.rollback()
                raise AppError("invalid_rule", "The YAML id must match the rule id.", 422)
            if rule.sha256 != row.sha256:
                self._new_version(row, rule, user_id=principal.user_id)
                detail.update(version=row.version, sha256=rule.sha256)
        if enabled is not None and enabled != row.enabled:
            row.enabled = enabled
            detail["enabled"] = enabled
        if detail:
            self.audit.record(
                "rule.updated",
                user_id=principal.user_id,
                meta=meta,
                object_type="rule",
                object_id=rule_id,
                detail=detail,
            )
        self.session.commit()
        return row

    # ------------------------------------------------------------------ test (pure)

    @staticmethod
    def test(yaml_text: str, events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        """Run one rule over sample events (ts-ordered and, for source detectors, in the given
        order as one source). Nothing is stored."""
        from app.detection.detectors import SourceInfo

        try:
            rule = load_rule(yaml_text)
        except RuleError as exc:
            raise _invalid(exc) from exc
        if len(events) > MAX_TEST_EVENTS:
            raise AppError("too_many_events", f"At most {MAX_TEST_EVENTS} events.", 422)
        engine = DetectionEngine([rule])
        ordered = sorted(events, key=lambda e: (e["ts"], str(e["id"])))
        for event in ordered:
            engine.feed(event)
        if engine.needs_sources:
            engine.feed_source(SourceInfo("sample", "sample"), list(events))
        return {
            "rule_id": rule.id,
            "kind": rule.kind,
            "matches": engine.matches.get(rule.id, 0),
            "alerts": [
                {
                    "dedup_key": d.dedup_key,
                    "title": d.title,
                    "event_count": d.count,
                    "event_ids": [str(r[0]) for r in d.refs],
                    "first_seen": d.first_seen,
                    "last_seen": d.last_seen,
                    "host": d.host,
                    "user": d.user,
                    "details": d.summary(),
                }
                for d in engine.results()
            ],
            "warnings": dict(engine.warnings),
        }

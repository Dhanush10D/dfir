"""Playbooks, runs, steps and four-eyes action approvals (guide 19.1, 19.2).

* The packaged playbooks are synced into ``playbooks`` under an advisory lock; rules managers can
  import custom ones. A run snapshots the definition and gets one ``playbook_run_steps`` row per
  step. ``dry_run`` returns the plan and writes nothing.
* Steps are ``manual`` (done or skipped by a person, with notes) or ``action`` (a handler from
  the closed registry). In the Standard profile the ``agent.*`` handlers execute nothing: the
  outcome is ``not_executed`` and the step waits until a person records that it was done by hand.
* An action that needs approval runs only through an ``action_requests`` row approved by someone
  with ``approve`` on the case who is not the requester. Requests can be rejected (or withdrawn
  by the requester) and expire. Execution moves the request ``approved -> finished`` under row
  locks, so it happens at most once; the handler's only effect is an outbox row written in the
  same transaction.
* Every read-modify-write locks, in this order, the case row (``FOR SHARE``; closing takes ``FOR
  UPDATE``), the run, the step and the request (``FOR UPDATE``), and re-checks state after the
  lock. Closed cases refuse every change. Database triggers and CHECK constraints enforce the
  same state machine and the four-eyes rule (migration 0012).
* Every step records who did what, when, with which result; the run carries the triggering
  alert. Everything is audited (parameters only as a hash).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import (
    AppError,
    ConflictError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
)
from app.core.permissions import Permission, Principal
from app.db.models import (
    ActionRequest,
    Alert,
    Case,
    CaseStatus,
    Playbook,
    PlaybookRun,
    PlaybookRunStep,
)
from app.integrations import messages as M  # noqa: N812
from app.response.registry import (
    ACTIONS,
    OUTCOME_COMPLETED,
    OUTCOME_NOT_EXECUTED,
    ActionContext,
    ActionParamError,
    ActionResult,
    clean_params,
    plan,
)
from app.response.schema import LoadedPlaybook, PlaybookError, builtin_texts, parse_playbook
from app.services.audit import AuditService, RequestMeta
from app.services.authz import CaseAccess, load_case_access, require_global
from app.services.outbox import emit_event

log = structlog.stdlib.get_logger("dfirbench.playbooks")

SYNC_LOCK = int.from_bytes(hashlib.sha256(b"dfir_playbooks_sync").digest()[:8], "big", signed=True)
MAX_NOTES = 4000
MAX_REASON = 2000
MAX_LIST = 200
OPEN_REQUEST = ("pending", "approved")
# Databases (by URL) whose packaged playbooks this process has already synced.
_SYNCED: set[str] = set()


def utcnow() -> datetime:
    return datetime.now(UTC)


def params_sha256(params: Mapping[str, Any]) -> str:
    encoded = json.dumps(dict(params), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode()).hexdigest()


def _clean_note(value: str | None, limit: int, what: str) -> str | None:
    if value is None:
        return None
    if "\x00" in value or len(value) > limit:
        raise AppError("invalid_request", f"{what} must be at most {limit} characters.", 422)
    return value.strip() or None


@dataclass(frozen=True)
class RunView:
    run: PlaybookRun
    steps: list[PlaybookRunStep]
    requests: list[ActionRequest]


class PlaybookService:
    def __init__(
        self, session: Session, settings: Settings, clock: Callable[[], datetime] = utcnow
    ) -> None:
        self.session = session
        self.settings = settings
        self.clock = clock
        self.audit = AuditService(session)

    # ------------------------------------------------------------------ catalogue

    def sync_builtin(self) -> dict[str, int]:
        """Upsert the packaged playbooks (version bump when a file changed). Commits."""
        counts = {"created": 0, "updated": 0, "unchanged": 0, "retired": 0}
        self.session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": SYNC_LOCK})
        shipped: list[str] = []
        for raw in builtin_texts().values():
            loaded = parse_playbook(raw)
            shipped.append(loaded.id)
            row = self.session.execute(
                select(Playbook).where(Playbook.id == loaded.id).with_for_update()
            ).scalar_one_or_none()
            if row is None:
                self.session.add(self._row(loaded, origin="builtin", user_id=None))
                counts["created"] += 1
            elif row.origin != "builtin":
                log.warning("builtin_playbook_id_taken", playbook_id=loaded.id)
            elif row.sha256 != loaded.sha256:
                self._apply(row, loaded)
                row.version += 1
                counts["updated"] += 1
            else:
                counts["unchanged"] += 1
        for row in self.session.execute(
            select(Playbook)
            .where(
                Playbook.origin == "builtin",
                Playbook.id.not_in(shipped),
                Playbook.enabled.is_(True),
            )
            .with_for_update()
        ).scalars():
            row.enabled = False  # no longer shipped; runs reference it, so it stays
            counts["retired"] += 1
        self.session.commit()
        return counts

    def _ensure_synced(self) -> None:
        bind = self.session.get_bind()
        key = str(getattr(bind, "url", bind))
        if key not in _SYNCED:
            self.sync_builtin()
            _SYNCED.add(key)

    def _apply(self, row: Playbook, loaded: LoadedPlaybook) -> None:
        definition = loaded.definition()
        row.title = loaded.model.title
        row.description = loaded.model.description or None
        row.trigger = definition["trigger"]
        row.steps = definition["phases"]
        row.notify = definition["notify"]
        row.raw_yaml = loaded.raw_yaml
        row.sha256 = loaded.sha256
        row.updated_at = self.clock()

    def _row(self, loaded: LoadedPlaybook, *, origin: str, user_id: uuid.UUID | None) -> Playbook:
        row = Playbook(id=loaded.id, version=1, enabled=True, origin=origin, created_by=user_id)
        self._apply(row, loaded)
        return row

    def list_playbooks(self, principal: Principal) -> list[Playbook]:
        self._ensure_synced()
        rows = list(
            self.session.execute(select(Playbook).order_by(Playbook.id).limit(MAX_LIST)).scalars()
        )
        self.session.commit()
        return rows

    def get_playbook(self, principal: Principal, playbook_id: str) -> Playbook:
        self._ensure_synced()
        row = self.session.get(Playbook, playbook_id)
        if row is None:
            raise NotFoundError("Playbook not found.")
        return row

    def import_yaml(self, principal: Principal, raw: str, meta: RequestMeta) -> Playbook:
        """Create or update a custom playbook from YAML (rules managers)."""
        require_global(principal, Permission.RULES_MANAGE)
        try:
            loaded = parse_playbook(raw)
        except PlaybookError as exc:
            raise AppError("invalid_playbook", str(exc), 422, {"errors": exc.errors[:50]}) from exc
        self._ensure_synced()
        row = self.session.execute(
            select(Playbook).where(Playbook.id == loaded.id).with_for_update()
        ).scalar_one_or_none()
        if row is not None and row.origin == "builtin":
            self.session.rollback()
            raise ConflictError(
                "A built-in playbook has this id; choose another id.", "playbook_id_taken"
            )
        if row is None:
            row = self._row(loaded, origin="custom", user_id=principal.user_id)
            self.session.add(row)
        elif row.sha256 != loaded.sha256:
            self._apply(row, loaded)
            row.version += 1
        self.session.flush()
        self.audit.record(
            "playbook.imported",
            user_id=principal.user_id,
            meta=meta,
            object_type="playbook",
            object_id=row.id,
            detail={"version": row.version, "sha256": row.sha256},
        )
        self.session.commit()
        return row

    def suggestions(self, principal: Principal, alert_id: uuid.UUID) -> list[Playbook]:
        """Playbooks whose trigger names the alert's rule or one of its techniques."""
        alert = self.session.get(Alert, alert_id)
        if alert is None:
            raise NotFoundError("Alert not found.")
        try:
            self._access(principal, alert.case_id)
        except NotFoundError as exc:
            raise NotFoundError("Alert not found.") from exc
        tags = set(alert.attack_tags or [])
        tags |= {t.split(".", 1)[0] for t in tags}
        out = []
        for row in self.list_playbooks(principal):
            trigger = row.trigger or {}
            rules = set(trigger.get("rules") or [])
            attack = set(trigger.get("attack") or [])
            if row.enabled and ((alert.rule_id and alert.rule_id in rules) or tags & attack):
                out.append(row)
        return out

    # ------------------------------------------------------------------ access and locks

    def _access(self, principal: Principal, case_id: uuid.UUID) -> CaseAccess:
        return load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )

    def _load_run(self, principal: Principal, run_id: uuid.UUID) -> tuple[PlaybookRun, CaseAccess]:
        run = self.session.get(PlaybookRun, run_id)
        if run is None:
            raise NotFoundError("Playbook run not found.")
        try:
            access = self._access(principal, run.case_id)
        except NotFoundError as exc:
            raise NotFoundError("Playbook run not found.") from exc
        return run, access

    def _fail(self, exc: AppError) -> AppError:
        """Release every lock of this transaction before reporting an error."""
        self.session.rollback()
        return exc

    def _lock_open_case(self, case_id: uuid.UUID) -> None:
        status = self.session.execute(
            select(Case.status).where(Case.id == case_id).with_for_update(read=True)
        ).scalar_one()
        if status is CaseStatus.closed:
            raise self._fail(InvalidStateError("The case is closed; its response is read-only."))

    def _lock_run(self, run_id: uuid.UUID) -> PlaybookRun:
        run = self.session.execute(
            select(PlaybookRun)
            .where(PlaybookRun.id == run_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()
        if run.status != "running":
            raise self._fail(
                InvalidStateError(f"The playbook run is {run.status}.", status=run.status)
            )
        return run

    def _lock_step(self, run_id: uuid.UUID, step_key: str) -> PlaybookRunStep:
        step = self.session.execute(
            select(PlaybookRunStep)
            .where(PlaybookRunStep.run_id == run_id, PlaybookRunStep.step_key == step_key)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if step is None:
            raise self._fail(NotFoundError("Playbook step not found."))
        return step

    def _lock_request(self, request_id: uuid.UUID) -> ActionRequest:
        return self.session.execute(
            select(ActionRequest)
            .where(ActionRequest.id == request_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()

    def _open_request(self, step_id: uuid.UUID) -> ActionRequest | None:
        """The step's pending/approved request, locked (at most one: partial UNIQUE index)."""
        return self.session.execute(
            select(ActionRequest)
            .where(ActionRequest.step_id == step_id, ActionRequest.status.in_(OPEN_REQUEST))
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()

    def _audit(
        self,
        event: str,
        principal: Principal,
        meta: RequestMeta | None,
        run: PlaybookRun,
        /,
        **detail: Any,
    ) -> None:
        self.audit.record(
            event,
            user_id=principal.user_id,
            meta=meta,
            object_type="playbook_run",
            object_id=run.id,
            detail={
                "case_id": str(run.case_id),
                "playbook_id": run.playbook_id,
                "alert_id": str(run.alert_id) if run.alert_id else None,
                **detail,
            },
        )

    # ------------------------------------------------------------------ expiry

    def expire_overdue(self, case_id: uuid.UUID) -> int:
        """Mark open requests of the case that are past ``expires_at`` as expired. Commits.

        Runs before every approval operation, so an expiry is recorded even when the operation
        that noticed it is then refused. Closed cases are left untouched.
        """
        now = self.clock()
        overdue = self.session.execute(
            select(ActionRequest.id, ActionRequest.run_id, ActionRequest.step_id)
            .where(
                ActionRequest.case_id == case_id,
                ActionRequest.status.in_(OPEN_REQUEST),
                ActionRequest.expires_at <= now,
            )
            .order_by(ActionRequest.requested_at, ActionRequest.id)
            .limit(MAX_LIST)
        ).all()
        if not overdue:
            self.session.commit()
            return 0
        status = self.session.execute(
            select(Case.status).where(Case.id == case_id).with_for_update(read=True)
        ).scalar_one()
        if status is CaseStatus.closed:
            self.session.commit()
            return 0
        count = 0
        for request_id, run_id, step_id in overdue:
            run = self.session.execute(
                select(PlaybookRun)
                .where(PlaybookRun.id == run_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            ).scalar_one()
            step = self.session.execute(
                select(PlaybookRunStep)
                .where(PlaybookRunStep.id == step_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            ).scalar_one()
            request = self._lock_request(request_id)
            if request.status not in OPEN_REQUEST or request.expires_at > now:
                continue  # decided or executed while we waited for the locks
            if request.status == "pending":
                request.decided_at = now
            request.status = "expired"
            self.session.flush()
            if run.status == "running" and step.status in ("awaiting_approval", "approved"):
                step.status = "pending"
                step.updated_at = now
                self.session.flush()
            self.audit.record(
                "playbook.action_expired",
                object_type="action_request",
                object_id=request.id,
                detail={
                    "case_id": str(case_id),
                    "run_id": str(run_id),
                    "step_key": step.step_key,
                    "action": request.action,
                },
            )
            count += 1
        self.session.commit()
        return count

    # ------------------------------------------------------------------ runs

    def _plan(self, playbook: Playbook, alert_id: uuid.UUID | None) -> dict[str, Any]:
        steps: list[dict[str, Any]] = []
        for phase in playbook.steps or []:
            for step in phase.get("steps") or []:
                action = step.get("action")
                entry: dict[str, Any] = {
                    "position": len(steps),
                    "phase": phase.get("name"),
                    "step_key": step.get("id"),
                    "text": step.get("text"),
                    "kind": "action" if action else "manual",
                    "action": action,
                    "requires_approval": bool(step.get("requires_approval")),
                }
                if action:
                    entry["plan"] = (
                        plan(
                            action,
                            step.get("params") or {},
                            requires_approval=bool(step.get("requires_approval")),
                        )
                        if action in ACTIONS
                        else {"action": action, "error": "unknown_action"}
                    )
                steps.append(entry)
        return {
            "dry_run": True,
            "writes": "none",
            "playbook": {
                "id": playbook.id,
                "version": playbook.version,
                "title": playbook.title,
                "sha256": playbook.sha256,
            },
            "alert_id": str(alert_id) if alert_id else None,
            "steps": steps,
            "approvals_needed": sum(1 for s in steps if s["requires_approval"]),
            "notifications": {
                "event": M.EVENT_RUN_STARTED,
                "channels": list((playbook.notify or {}).get("channels") or []),
                "roles": list((playbook.notify or {}).get("roles") or []),
            },
        }

    def start_run(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        meta: RequestMeta,
        *,
        playbook_id: str,
        alert_id: uuid.UUID | None = None,
        dry_run: bool = False,
    ) -> RunView | dict[str, Any]:
        access = self._access(principal, case_id)
        access.require(Permission.INVESTIGATE)
        playbook = self.get_playbook(principal, playbook_id)
        if not playbook.enabled:
            raise InvalidStateError("This playbook is disabled.")
        if alert_id is not None:
            alert = self.session.get(Alert, alert_id)
            if alert is None or alert.case_id != case_id:
                raise NotFoundError("Alert not found in this case.")
        if dry_run:
            result = self._plan(playbook, alert_id)
            self.session.rollback()  # nothing was written; end the read transaction
            return result
        self._lock_open_case(case_id)
        playbook = self.session.execute(
            select(Playbook)
            .where(Playbook.id == playbook_id)
            .with_for_update(read=True)
            .execution_options(populate_existing=True)
        ).scalar_one()
        now = self.clock()
        run = PlaybookRun(
            id=uuid.uuid4(),
            case_id=case_id,
            playbook_id=playbook.id,
            playbook_version=playbook.version,
            playbook_sha256=playbook.sha256,
            status="running",
            alert_id=alert_id,
            started_by=principal.user_id,
            started_at=now,
            definition={
                "id": playbook.id,
                "title": playbook.title,
                "description": playbook.description,
                "version": playbook.version,
                "trigger": playbook.trigger,
                "phases": playbook.steps,
                "notify": playbook.notify,
            },
        )
        self.session.add(run)
        self.session.flush()
        steps: list[PlaybookRunStep] = []
        for phase in playbook.steps or []:
            for item in phase.get("steps") or []:
                action = item.get("action")
                if action is not None and action not in ACTIONS:
                    raise self._fail(
                        AppError(
                            "invalid_playbook",
                            "The playbook names an action this version does not have.",
                            409,
                            {"action": str(action)[:64]},
                        )
                    )
                steps.append(
                    PlaybookRunStep(
                        id=uuid.uuid4(),
                        run_id=run.id,
                        case_id=case_id,
                        position=len(steps),
                        phase=str(phase.get("name")),
                        step_key=str(item.get("id")),
                        text=str(item.get("text")),
                        kind="action" if action else "manual",
                        action=action,
                        params=dict(item.get("params") or {}),
                        requires_approval=bool(
                            action and (item.get("requires_approval") or ACTIONS[action].impact)
                        ),
                        status="pending",
                        updated_by=principal.user_id,
                        updated_at=now,
                    )
                )
        self.session.add_all(steps)
        self.session.flush()
        notify = playbook.notify or {}
        emit_event(
            self.session,
            M.EVENT_RUN_STARTED,
            case_id=case_id,
            payload={
                "run_id": str(run.id),
                "playbook_id": playbook.id,
                "alert_id": str(alert_id) if alert_id else None,
                "actor_id": str(principal.user_id),
                "notify_channels": list(notify.get("channels") or []),
                "notify_roles": list(notify.get("roles") or []),
            },
            dedup_key=f"{M.EVENT_RUN_STARTED}:{run.id}",
        )
        self._audit(
            "playbook.run_started",
            principal,
            meta,
            run,
            playbook_version=playbook.version,
            playbook_sha256=playbook.sha256,
            steps=len(steps),
        )
        self.session.commit()
        return RunView(run, steps, [])

    def list_runs(self, principal: Principal, case_id: uuid.UUID) -> list[PlaybookRun]:
        self._access(principal, case_id).require(Permission.CASE_READ)
        rows = list(
            self.session.execute(
                select(PlaybookRun)
                .where(PlaybookRun.case_id == case_id)
                .order_by(PlaybookRun.started_at.desc(), PlaybookRun.id)
                .limit(MAX_LIST)
            ).scalars()
        )
        self.session.commit()
        return rows

    def _view(self, run: PlaybookRun) -> RunView:
        steps = list(
            self.session.execute(
                select(PlaybookRunStep)
                .where(PlaybookRunStep.run_id == run.id)
                .order_by(PlaybookRunStep.position)
                .execution_options(populate_existing=True)
            ).scalars()
        )
        requests = list(
            self.session.execute(
                select(ActionRequest)
                .where(ActionRequest.run_id == run.id)
                .order_by(ActionRequest.requested_at, ActionRequest.id)
                .execution_options(populate_existing=True)
            ).scalars()
        )
        return RunView(run, steps, requests)

    def get_run(self, principal: Principal, run_id: uuid.UUID) -> RunView:
        run, access = self._load_run(principal, run_id)
        access.require(Permission.CASE_READ)
        self.expire_overdue(run.case_id)
        self.session.refresh(run)
        view = self._view(run)
        self.session.commit()
        return view

    def cancel_run(
        self, principal: Principal, run_id: uuid.UUID, meta: RequestMeta, *, reason: str
    ) -> RunView:
        run, access = self._load_run(principal, run_id)
        access.require(Permission.INVESTIGATE)
        why = _clean_note(reason, MAX_REASON, "The reason")
        if not why:
            raise AppError("reason_required", "A reason is required to cancel a run.", 422)
        self.expire_overdue(run.case_id)
        self._lock_open_case(run.case_id)
        run = self._lock_run(run_id)
        now = self.clock()
        # Pending requests are closed; an approved one can no longer run and expires on its own.
        pending = self.session.execute(
            select(ActionRequest)
            .where(ActionRequest.run_id == run_id, ActionRequest.status == "pending")
            .order_by(ActionRequest.requested_at, ActionRequest.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalars()
        rejected = 0
        for request in pending:
            request.status = "rejected"
            request.decided_by = principal.user_id
            request.decided_at = now
            request.decision_reason = "run cancelled"
            rejected += 1
        self.session.flush()
        run.status = "cancelled"
        run.finished_at = now
        self._audit(
            "playbook.run_cancelled", principal, meta, run, reason=why, requests_closed=rejected
        )
        self.session.commit()
        return self._view(run)

    # ------------------------------------------------------------------ steps

    def _handler_result(
        self,
        principal: Principal,
        run: PlaybookRun,
        step: PlaybookRunStep,
        params: Mapping[str, Any],
        dedup: str,
    ) -> ActionResult:
        spec = ACTIONS.get(step.action or "")  # a dict lookup: the registry is the allowlist
        if spec is None:
            return ActionResult("failed", {"error": "unknown_action"})

        def emit(event_type: str, payload: dict[str, Any], dedup_key: str) -> None:
            outcome = emit_event(
                self.session,
                event_type,
                case_id=run.case_id,
                payload={**payload, "actor_id": str(principal.user_id)},
                dedup_key=f"{dedup_key}:{dedup}",
            )
            if outcome == "error":
                raise AppError("event_not_queued", "The notification could not be queued.", 503)

        ctx = ActionContext(
            case_id=str(run.case_id),
            run_id=str(run.id),
            playbook_id=run.playbook_id,
            step_key=step.step_key,
            alert_id=str(run.alert_id) if run.alert_id else None,
            params=dict(params),
            emit=emit,
        )
        try:
            with self.session.begin_nested():
                return spec.handler(ctx)
        except AppError as exc:
            return ActionResult("failed", {"error": exc.code})

    @staticmethod
    def _step_status(outcome: str) -> str:
        if outcome == OUTCOME_COMPLETED:
            return "done"
        return "not_executed" if outcome == OUTCOME_NOT_EXECUTED else "failed"

    def _finish_step(
        self,
        step: PlaybookRunStep,
        principal: Principal,
        *,
        status: str,
        outcome: str,
        result: dict[str, Any] | None,
        notes: str | None,
    ) -> None:
        now = self.clock()
        step.status = status
        step.outcome = outcome
        step.result = result
        if notes is not None:
            step.notes = notes
        step.updated_by = principal.user_id
        step.updated_at = now
        if status in ("done", "skipped"):
            step.completed_by = principal.user_id
            step.completed_at = now
        self.session.flush()

    def _maybe_complete(self, run: PlaybookRun) -> bool:
        open_steps = self.session.execute(
            select(PlaybookRunStep.id)
            .where(
                PlaybookRunStep.run_id == run.id,
                PlaybookRunStep.status.not_in(("done", "skipped")),
            )
            .limit(1)
        ).scalar_one_or_none()
        if open_steps is not None:
            return False
        run.status = "completed"
        run.finished_at = self.clock()
        self.session.flush()
        return True

    def _effective_params(
        self, step: PlaybookRunStep, params: Mapping[str, Any] | None
    ) -> dict[str, Any]:
        merged = {**(step.params or {}), **dict(params or {})}
        try:
            return clean_params(step.action or "", merged, require=True)
        except ActionParamError as exc:
            raise self._fail(AppError("invalid_params", str(exc), 422)) from exc

    def step_op(
        self,
        principal: Principal,
        run_id: uuid.UUID,
        step_key: str,
        meta: RequestMeta,
        *,
        op: str,
        notes: str | None = None,
        params: Mapping[str, Any] | None = None,
        dry_run: bool = False,
        idempotency_key: str | None = None,
    ) -> RunView | dict[str, Any]:
        run, access = self._load_run(principal, run_id)
        access.require(Permission.INVESTIGATE)
        note = _clean_note(notes, MAX_NOTES, "Notes")
        if op not in ("complete", "skip", "request", "execute"):
            raise AppError("invalid_request", "Unknown step operation.", 422)
        if dry_run:
            return self._dry_step(run, step_key, op, params)
        self.expire_overdue(run.case_id)
        self._lock_open_case(run.case_id)
        run = self._lock_run(run_id)
        step = self._lock_step(run_id, step_key)
        detail: dict[str, Any] = {"step_key": step.step_key, "op": op, "action": step.action}
        if op == "complete":
            self._complete(principal, step, note)
            action = "playbook.step_completed"
            detail["outcome"] = step.outcome
        elif op == "skip":
            if step.status not in ("pending", "failed", "not_executed"):
                raise self._fail(
                    InvalidStateError("This step cannot be skipped now.", status=step.status)
                )
            if not note:
                raise self._fail(AppError("reason_required", "Say why the step is skipped.", 422))
            self._finish_step(
                step, principal, status="skipped", outcome="skipped", result=step.result, notes=note
            )
            action = "playbook.step_skipped"
        elif op == "request":
            request = self._request(principal, run, step, params, idempotency_key)
            action = "playbook.action_requested"
            detail.update(request_id=str(request.id), params_sha256=request.params_sha256)
        else:
            request_id, outcome, digest = self._execute(principal, run, step, params, note)
            action = "playbook.action_executed"
            detail.update(request_id=request_id, outcome=outcome, params_sha256=digest)
        completed = self._maybe_complete(run)
        self._audit(action, principal, meta, run, **detail)
        if completed:
            self._audit("playbook.run_completed", principal, meta, run)
        self.session.commit()
        return self._view(run)

    def _dry_step(
        self, run: PlaybookRun, step_key: str, op: str, params: Mapping[str, Any] | None
    ) -> dict[str, Any]:
        step = self.session.execute(
            select(PlaybookRunStep).where(
                PlaybookRunStep.run_id == run.id, PlaybookRunStep.step_key == step_key
            )
        ).scalar_one_or_none()
        if step is None:
            raise NotFoundError("Playbook step not found.")
        out: dict[str, Any] = {
            "dry_run": True,
            "writes": "none",
            "op": op,
            "step_key": step.step_key,
            "status": step.status,
            "kind": step.kind,
        }
        if step.action and step.action in ACTIONS:
            merged = {**(step.params or {}), **dict(params or {})}
            try:
                merged = clean_params(step.action, merged, require=False)
            except ActionParamError as exc:
                self.session.rollback()
                raise AppError("invalid_params", str(exc), 422) from exc
            out["plan"] = plan(step.action, merged, requires_approval=step.requires_approval)
        self.session.rollback()
        return out

    def _complete(self, principal: Principal, step: PlaybookRunStep, note: str | None) -> None:
        if step.kind == "manual":
            if step.status != "pending":
                raise self._fail(InvalidStateError("This step is not open.", status=step.status))
            self._finish_step(
                step, principal, status="done", outcome="completed", result=None, notes=note
            )
            return
        if step.status != "not_executed":
            raise self._fail(
                InvalidStateError(
                    "An action step is run with 'execute'; it can be completed by hand only "
                    "after the platform recorded that it did not execute it.",
                    status=step.status,
                )
            )
        if not note:
            raise self._fail(
                AppError("notes_required", "Record how and where the action was carried out.", 422)
            )
        self._finish_step(
            step,
            principal,
            status="done",
            outcome="completed_manually",
            result={**(step.result or {}), "completed_manually": True},
            notes=note,
        )

    def _request(
        self,
        principal: Principal,
        run: PlaybookRun,
        step: PlaybookRunStep,
        params: Mapping[str, Any] | None,
        idempotency_key: str | None,
    ) -> ActionRequest:
        if step.kind != "action":
            raise self._fail(InvalidStateError("A manual step needs no approval."))
        if not step.requires_approval:
            raise self._fail(
                InvalidStateError("This action needs no approval; run it with 'execute'.")
            )
        key = hashlib.sha256(
            f"{run.id}:{step.step_key}:{idempotency_key or uuid.uuid4()}".encode()
        ).hexdigest()
        if idempotency_key:
            previous = self.session.execute(
                select(ActionRequest).where(ActionRequest.idempotency_key == key)
            ).scalar_one_or_none()
            if previous is not None:
                return previous  # the same request sent again: nothing changes
        if step.status not in ("pending", "failed"):
            raise self._fail(
                InvalidStateError(
                    "This step already has a request or a result.", status=step.status
                )
            )
        effective = self._effective_params(step, params)
        now = self.clock()
        request = ActionRequest(
            id=uuid.uuid4(),
            case_id=run.case_id,
            run_id=run.id,
            step_id=step.id,
            alert_id=run.alert_id,
            action=step.action or "",
            params=effective,
            params_sha256=params_sha256(effective),
            idempotency_key=key,
            status="pending",
            requested_by=principal.user_id,
            requested_at=now,
            expires_at=now + timedelta(minutes=self.settings.approval_ttl_minutes),
        )
        self.session.add(request)
        try:
            self.session.flush()
        except IntegrityError as exc:
            raise self._fail(
                ConflictError("This step already has an open request.", "request_exists")
            ) from exc
        step.status = "awaiting_approval"
        step.outcome = None
        step.result = None
        step.updated_by = principal.user_id
        step.updated_at = now
        self.session.flush()
        emit_event(
            self.session,
            M.EVENT_APPROVAL_REQUESTED,
            case_id=run.case_id,
            payload={
                "request_id": str(request.id),
                "run_id": str(run.id),
                "playbook_id": run.playbook_id,
                "step_key": step.step_key,
                "action": request.action,
                "expires_at": request.expires_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "actor_id": str(principal.user_id),
            },
            dedup_key=f"{M.EVENT_APPROVAL_REQUESTED}:{request.id}",
        )
        return request

    def _execute(
        self,
        principal: Principal,
        run: PlaybookRun,
        step: PlaybookRunStep,
        params: Mapping[str, Any] | None,
        note: str | None,
    ) -> tuple[str | None, str, str]:
        if step.kind != "action":
            raise self._fail(InvalidStateError("A manual step is completed, not executed."))
        now = self.clock()
        if step.requires_approval:
            if step.status != "approved":
                raise self._fail(
                    AppError(
                        "approval_required",
                        "This action needs an approval by a second person before it can run.",
                        409,
                        {"status": step.status},
                    )
                )
            request = self._open_request(step.id)
            # Re-check under the lock: decided, expired or already executed in the meantime?
            if request is None or request.status != "approved" or request.expires_at <= now:
                raise self._fail(
                    AppError("approval_required", "There is no valid approval for this step.", 409)
                )
            if params and params_sha256(self._effective_params(step, params)) != (
                request.params_sha256
            ):
                raise self._fail(
                    ConflictError(
                        "The approval covers different parameters; request a new approval.",
                        "params_changed",
                    )
                )
            result = self._handler_result(principal, run, step, request.params, str(request.id))
            request.status = "finished"
            request.executed_by = principal.user_id
            request.executed_at = now
            request.outcome = result.outcome
            request.result = result.detail
            self.session.flush()  # the step trigger looks at the finished request
            self._finish_step(
                step,
                principal,
                status=self._step_status(result.outcome),
                outcome=result.outcome,
                result={**result.detail, "request_id": str(request.id)},
                notes=note,
            )
            return str(request.id), result.outcome, request.params_sha256
        if step.status not in ("pending", "failed"):
            raise self._fail(InvalidStateError("This step is not open.", status=step.status))
        effective = self._effective_params(step, params)
        digest = params_sha256(effective)
        result = self._handler_result(principal, run, step, effective, str(step.id))
        self._finish_step(
            step,
            principal,
            status=self._step_status(result.outcome),
            outcome=result.outcome,
            result={**result.detail, "params": effective},
            notes=note,
        )
        return None, result.outcome, digest

    # ------------------------------------------------------------------ approvals

    def list_requests(
        self, principal: Principal, case_id: uuid.UUID, status: str | None = None
    ) -> list[ActionRequest]:
        self._access(principal, case_id).require(Permission.CASE_READ)
        self.expire_overdue(case_id)
        conds = [ActionRequest.case_id == case_id]
        if status:
            conds.append(ActionRequest.status == status)
        rows = list(
            self.session.execute(
                select(ActionRequest)
                .where(*conds)
                .order_by(ActionRequest.requested_at.desc(), ActionRequest.id)
                .limit(MAX_LIST)
            ).scalars()
        )
        self.session.commit()
        return rows

    def _load_request(
        self, principal: Principal, request_id: uuid.UUID
    ) -> tuple[ActionRequest, CaseAccess]:
        request = self.session.get(ActionRequest, request_id)
        if request is None:
            raise NotFoundError("Action request not found.")
        try:
            access = self._access(principal, request.case_id)
        except NotFoundError as exc:
            raise NotFoundError("Action request not found.") from exc
        return request, access

    def _decide(
        self,
        principal: Principal,
        request_id: uuid.UUID,
        meta: RequestMeta,
        *,
        approve: bool,
        reason: str | None,
    ) -> ActionRequest:
        request, access = self._load_request(principal, request_id)
        withdraw = not approve and request.requested_by == principal.user_id
        access.require(Permission.INVESTIGATE if withdraw else Permission.APPROVE)
        if approve and request.requested_by == principal.user_id:
            raise ForbiddenError(
                "An action must be approved by someone other than the person who requested it.",
                rule="four_eyes",
            )
        why = _clean_note(reason, MAX_REASON, "The reason")
        if not approve and not why:
            raise AppError("reason_required", "A reason is required to reject a request.", 422)
        case_id, run_id, step_id = request.case_id, request.run_id, request.step_id
        self.expire_overdue(case_id)
        self._lock_open_case(case_id)
        run = self._lock_run(run_id)
        step = self.session.execute(
            select(PlaybookRunStep)
            .where(PlaybookRunStep.id == step_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()
        request = self._lock_request(request_id)
        now = self.clock()
        # Re-check under the locks: a concurrent decision or the expiry may have won.
        if request.status != "pending" or step.status != "awaiting_approval":
            raise self._fail(
                InvalidStateError(
                    f"The request is {request.status}; only a pending request can be decided.",
                    status=request.status,
                )
            )
        if request.expires_at <= now:
            raise self._fail(AppError("approval_expired", "The request has expired.", 409))
        if approve and request.requested_by == principal.user_id:
            raise self._fail(
                ForbiddenError("The requester cannot approve the request.", rule="four_eyes")
            )
        request.status = "approved" if approve else "rejected"
        request.decided_by = principal.user_id
        request.decided_at = now
        request.decision_reason = why
        self.session.flush()  # the step trigger looks at the decided request
        step.status = "approved" if approve else "pending"
        step.updated_by = principal.user_id
        step.updated_at = now
        self.session.flush()
        self._audit(
            "playbook.action_approved" if approve else "playbook.action_rejected",
            principal,
            meta,
            run,
            request_id=str(request.id),
            step_key=step.step_key,
            action=request.action,
            requested_by=str(request.requested_by),
            params_sha256=request.params_sha256,
            withdrawn=withdraw,
            reason=why,
        )
        self.session.commit()
        return request

    def approve(
        self,
        principal: Principal,
        request_id: uuid.UUID,
        meta: RequestMeta,
        *,
        reason: str | None = None,
    ) -> ActionRequest:
        return self._decide(principal, request_id, meta, approve=True, reason=reason)

    def reject(
        self, principal: Principal, request_id: uuid.UUID, meta: RequestMeta, *, reason: str
    ) -> ActionRequest:
        return self._decide(principal, request_id, meta, approve=False, reason=reason)

    def requests_of(self, steps: Sequence[PlaybookRunStep]) -> dict[uuid.UUID, ActionRequest]:
        """The newest request per step (for views)."""
        ids = [s.id for s in steps]
        if not ids:
            return {}
        rows = self.session.execute(
            select(ActionRequest)
            .where(ActionRequest.step_id.in_(ids))
            .order_by(ActionRequest.requested_at, ActionRequest.id)
        ).scalars()
        return {r.step_id: r for r in rows}

"""Closed allowlist of playbook actions (guide 19.2). Pure.

A playbook step names an action; the name must be a key of :data:`ACTIONS`. Handlers are looked
up in that dict and nowhere else: there is no import by name, attribute lookup or evaluation of
playbook text. A handler may only describe its work (:func:`plan`) or do it through the narrow
:class:`ActionContext` it is given, inside the caller's database transaction.

Standard profile: there is no remote agent (guide 9.4 is P2). The ``agent.*`` actions therefore
have no executor. Running one records the outcome ``not_executed`` with the reason, and the step
stays open until a person records that the work was done by hand. Nothing here ever reports that
a host was isolated, a process killed or an account disabled.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from app.integrations.messages import EVENT_PLAYBOOK_NOTICE

OUTCOME_COMPLETED = "completed"
OUTCOME_NOT_EXECUTED = "not_executed"
NO_AGENT_REASON = "no_remote_agent"
NO_AGENT_MESSAGE = (
    "Not executed: the Standard profile has no remote agent, so the platform did nothing on the "
    "endpoint. Carry the action out by hand (EDR console, directory service) and record it on "
    "the step."
)
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
MAX_PARAM_CHARS = 255


class ActionParamError(ValueError):
    pass


@dataclass(frozen=True)
class ParamSpec:
    kind: str = "text"  # text | int
    required: bool = False


@dataclass(frozen=True)
class ActionResult:
    outcome: str  # completed | not_executed
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionContext:
    """What a handler may touch: its inputs and one way to queue an outbound event."""

    case_id: str
    run_id: str
    playbook_id: str
    step_key: str
    alert_id: str | None
    params: Mapping[str, Any]
    # (event type, payload, dedup key): written to the outbox in the caller's transaction.
    emit: Callable[[str, dict[str, Any], str], None]


Handler = Callable[[ActionContext], ActionResult]


@dataclass(frozen=True)
class ActionSpec:
    name: str
    title: str
    impact: bool  # impactful: approval by a second person is always required
    executor: str  # "none" = no executor in this profile; "platform" = done by dfirbench
    effect: str  # what running it does here (shown in dry runs)
    handler: Handler
    params: Mapping[str, ParamSpec] = field(default_factory=dict)


def _no_agent(ctx: ActionContext) -> ActionResult:
    return ActionResult(
        OUTCOME_NOT_EXECUTED,
        {"reason": NO_AGENT_REASON, "message": NO_AGENT_MESSAGE, "simulated": True},
    )


def _notify_team(ctx: ActionContext) -> ActionResult:
    ctx.emit(
        EVENT_PLAYBOOK_NOTICE,
        {"run_id": ctx.run_id, "playbook_id": ctx.playbook_id, "step_key": ctx.step_key},
        f"{EVENT_PLAYBOOK_NOTICE}:{ctx.run_id}:{ctx.step_key}",
    )
    return ActionResult(OUTCOME_COMPLETED, {"event": EVENT_PLAYBOOK_NOTICE})


_NO_AGENT_EFFECT = (
    "Nothing is changed on any endpoint (no remote agent in the Standard profile); the request, "
    "approval and outcome 'not_executed' are recorded and the step waits for manual completion."
)
_HOST = {"host": ParamSpec("text", required=True)}

ACTIONS: dict[str, ActionSpec] = {
    spec.name: spec
    for spec in (
        ActionSpec(
            "agent.isolate_host",
            "Isolate a host from the network",
            impact=True,
            executor="none",
            effect=_NO_AGENT_EFFECT,
            handler=_no_agent,
            params=_HOST,
        ),
        ActionSpec(
            "agent.kill_process",
            "Kill a process on a host",
            impact=True,
            executor="none",
            effect=_NO_AGENT_EFFECT,
            handler=_no_agent,
            params={**_HOST, "pid": ParamSpec("int"), "process": ParamSpec("text")},
        ),
        ActionSpec(
            "agent.disable_account",
            "Disable a user account",
            impact=True,
            executor="none",
            effect=_NO_AGENT_EFFECT,
            handler=_no_agent,
            params={"account": ParamSpec("text", required=True), "host": ParamSpec("text")},
        ),
        ActionSpec(
            "agent.memory_dump",
            "Collect a memory image from a host",
            impact=False,
            executor="none",
            effect=_NO_AGENT_EFFECT,
            handler=_no_agent,
            params=_HOST,
        ),
        ActionSpec(
            "agent.collect_triage",
            "Collect a triage bundle from a host",
            impact=False,
            executor="none",
            effect=_NO_AGENT_EFFECT,
            handler=_no_agent,
            params=_HOST,
        ),
        ActionSpec(
            "notify.team",
            "Notify the response team",
            impact=False,
            executor="platform",
            effect=(
                "Queues one 'playbook.notice' event for the configured notification channels "
                "(identifiers only, no evidence content)."
            ),
            handler=_notify_team,
        ),
    )
}


def clean_params(action: str, params: Mapping[str, Any], *, require: bool) -> dict[str, Any]:
    """Validate parameters against the action's spec (unknown names and types are refused)."""
    spec = ACTIONS[action]
    out: dict[str, Any] = {}
    for name, value in params.items():
        param = spec.params.get(name)
        if param is None:
            raise ActionParamError(f"action {action} has no parameter {str(name)[:40]!r}")
        if param.kind == "int":
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**31:
                raise ActionParamError(f"parameter {name!r} must be a non-negative integer")
            out[name] = value
        else:
            if not isinstance(value, str) or not value.strip():
                raise ActionParamError(f"parameter {name!r} must be non-empty text")
            if CONTROL_RE.search(value) or len(value) > MAX_PARAM_CHARS:
                raise ActionParamError(
                    f"parameter {name!r} must be one line of at most {MAX_PARAM_CHARS} characters"
                )
            out[name] = value.strip()
    if require:
        missing = sorted(n for n, p in spec.params.items() if p.required and n not in out)
        if missing:
            raise ActionParamError(f"action {action} needs: {', '.join(missing)}")
    return out


def plan(action: str, params: Mapping[str, Any], *, requires_approval: bool) -> dict[str, Any]:
    """What running the action would do (dry run). Changes nothing."""
    spec = ACTIONS[action]
    return {
        "action": spec.name,
        "title": spec.title,
        "impact": spec.impact,
        "requires_approval": bool(requires_approval or spec.impact),
        "executor": spec.executor,
        "would_execute": spec.executor == "platform",
        "effect": spec.effect,
        "params": dict(params),
        "missing_params": sorted(
            n for n, p in spec.params.items() if p.required and n not in params
        ),
    }

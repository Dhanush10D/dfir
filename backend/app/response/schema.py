"""Playbook format (guide 19.1) and its loader. Pure.

Hostile-input rules: ``yaml.safe_load`` only, through :func:`app.detection.yamlsafe.safe_yaml`
(size, node and nesting caps checked on the event stream, anchors/aliases refused), duplicate
mapping keys refused, then a strict Pydantic schema (unknown keys and wrong types are errors, no
type coercion), unique step ids and phase names, and action names that must exist in the closed
registry. An impactful action always requires approval, whatever the file says.
"""

from __future__ import annotations

import hashlib
import re
from importlib import resources
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.detection.yamlsafe import YamlInputError, safe_yaml
from app.response.registry import ACTIONS, ActionParamError, clean_params

MAX_PLAYBOOK_BYTES = 64 * 1024
MAX_PLAYBOOK_NODES = 5000
MAX_PLAYBOOK_DEPTH = 8
MAX_STEPS = 200

PLAYBOOK_ID_PATTERN = r"^PB-[A-Z0-9]{1,24}(-[A-Z0-9]{1,24}){0,4}$"
STEP_ID_PATTERN = r"^[a-z][a-z0-9_-]{0,31}$"
PLAYBOOK_ID_RE = re.compile(PLAYBOOK_ID_PATTERN)

StepId = Annotated[str, Field(pattern=STEP_ID_PATTERN)]
Technique = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]
RuleId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]
ParamValue = str | int


class PlaybookError(ValueError):
    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or [message]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class StepModel(_Strict):
    id: StepId
    text: str = Field(min_length=1, max_length=500)
    manual: bool = False
    action: str | None = Field(default=None, max_length=64)
    params: dict[str, ParamValue] = Field(default_factory=dict, max_length=8)
    requires_approval: bool = False

    @model_validator(mode="after")
    def _check(self) -> StepModel:
        if self.manual == (self.action is not None):
            raise ValueError("a step is either 'manual: true' or has an 'action'")
        if self.action is None:
            if self.params or self.requires_approval:
                raise ValueError("a manual step has no params and no approval")
            return self
        if self.action not in ACTIONS:
            raise ValueError(f"unknown action (allowed: {', '.join(sorted(ACTIONS))})")
        try:
            clean_params(self.action, self.params, require=False)
        except ActionParamError as exc:
            raise ValueError(str(exc)) from exc
        return self

    @property
    def kind(self) -> str:
        return "manual" if self.manual else "action"

    @property
    def needs_approval(self) -> bool:
        """The registry decides for impactful actions; the file can only add approval."""
        return self.action is not None and (self.requires_approval or ACTIONS[self.action].impact)


class PhaseModel(_Strict):
    name: str = Field(min_length=1, max_length=100)
    steps: list[StepModel] = Field(min_length=1, max_length=50)


class TriggerModel(_Strict):
    attack: list[Technique] = Field(default_factory=list, max_length=50)
    rules: list[RuleId] = Field(default_factory=list, max_length=100)


class NotifyModel(_Strict):
    channels: list[Literal["in_app", "slack", "teams", "email", "webhook"]] = Field(
        default_factory=list, max_length=5
    )
    roles: list[Literal["admin", "lead", "analyst"]] = Field(default_factory=list, max_length=3)


class PlaybookModel(_Strict):
    id: str = Field(pattern=PLAYBOOK_ID_PATTERN, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    trigger: TriggerModel = Field(default_factory=TriggerModel)
    phases: list[PhaseModel] = Field(min_length=1, max_length=20)
    notify: NotifyModel = Field(default_factory=NotifyModel)

    @model_validator(mode="after")
    def _unique(self) -> PlaybookModel:
        names = [p.name for p in self.phases]
        if len(set(names)) != len(names):
            raise ValueError("phase names must be unique")
        ids = [s.id for p in self.phases for s in p.steps]
        if len(ids) > MAX_STEPS:
            raise ValueError(f"at most {MAX_STEPS} steps")
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate step ids: {', '.join(dupes)}")
        return self

    def flat_steps(self) -> list[tuple[int, str, StepModel]]:
        """(position, phase name, step) in file order."""
        out: list[tuple[int, str, StepModel]] = []
        for phase in self.phases:
            for step in phase.steps:
                out.append((len(out), phase.name, step))
        return out


class LoadedPlaybook:
    def __init__(self, model: PlaybookModel, raw_yaml: str) -> None:
        self.model = model
        self.raw_yaml = raw_yaml
        self.sha256 = hashlib.sha256(raw_yaml.encode("utf-8")).hexdigest()

    @property
    def id(self) -> str:
        return self.model.id

    def definition(self) -> dict[str, Any]:
        """JSON form stored with the playbook and snapshotted into every run."""
        data = self.model.model_dump(mode="json")
        for phase in data["phases"]:
            for step in phase["steps"]:
                action = step.get("action")
                step["requires_approval"] = bool(
                    action and (step["requires_approval"] or ACTIONS[action].impact)
                )
        return data


def _reject_duplicate_keys(node: yaml.Node | None) -> None:
    if isinstance(node, yaml.MappingNode):
        seen: set[str] = set()
        for key, value in node.value:
            name = str(getattr(key, "value", ""))
            if name in seen:
                raise PlaybookError(f"duplicate key {name[:40]!r}")
            seen.add(name)
            _reject_duplicate_keys(value)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _reject_duplicate_keys(item)


def parse_playbook(text: str) -> LoadedPlaybook:
    try:
        data = safe_yaml(
            text,
            max_bytes=MAX_PLAYBOOK_BYTES,
            max_nodes=MAX_PLAYBOOK_NODES,
            max_depth=MAX_PLAYBOOK_DEPTH,
        )
        # The caps above already ran on the event stream; composing is now bounded.
        _reject_duplicate_keys(yaml.compose(text, Loader=yaml.SafeLoader))
    except YamlInputError as exc:
        raise PlaybookError(str(exc)) from exc
    except yaml.YAMLError as exc:
        raise PlaybookError("invalid YAML") from exc
    if not isinstance(data, dict):
        raise PlaybookError("a playbook is a YAML mapping")
    try:
        model = PlaybookModel.model_validate(data)
    except ValidationError as exc:
        errors = [
            f"{'.'.join(str(p) for p in err['loc']) or 'playbook'}: {err['msg']}"[:300]
            for err in exc.errors(include_url=False, include_input=False)[:50]
        ]
        raise PlaybookError("invalid playbook", errors) from exc
    return LoadedPlaybook(model, text)


def builtin_texts() -> dict[str, str]:
    """``{file stem: YAML text}`` of the starter playbooks, sorted by name."""
    root = resources.files("app.response.builtin")
    out: dict[str, str] = {}
    for item in sorted(root.iterdir(), key=lambda p: p.name):
        if item.name.endswith(".yml"):
            out[item.name[: -len(".yml")]] = item.read_text(encoding="utf-8")
    return out


def builtin_playbooks() -> list[LoadedPlaybook]:
    return [parse_playbook(text) for text in builtin_texts().values()]

"""Triage bundle manifest ``dfirbench.triage/1`` (docs/collection.md). Hostile input.

Validation is strict where the platform relies on a value (schema id, paths, hashes, sizes, times
with an explicit zone, unique paths, duplicate JSON keys refused) and forgiving elsewhere (unknown
keys are ignored so newer collectors stay readable). Every string is bounded and cleaned of NUL
characters and lone surrogates, because manifest values end up in jsonb run manifests and signed
custody entries.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from app.collection.names import MAX_NAME_CHARS, unsafe_name_reason
from app.parsers.normalize import clean_text

SCHEMA = "dfirbench.triage/1"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_LIST = 100_000


def _clean(value: str) -> str:
    return clean_text(value, 4096) or ""


Text = Annotated[str, Field(max_length=8192), AfterValidator(_clean)]
Short = Annotated[str, Field(max_length=512), AfterValidator(_clean)]
Hex64 = Annotated[str, Field(pattern=r"^[0-9a-fA-F]{64}$"), AfterValidator(str.lower)]


class ManifestError(ValueError):
    """The manifest is missing, unreadable or does not match the schema."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class CollectorInfo(_Model):
    name: Short = Field(min_length=1)
    version: Short = Field(min_length=1)
    sha256: Hex64 | None = None
    runtime: Short | None = None


class HostInfo(_Model):
    hostname: Short | None = None
    fqdn: Short | None = None
    os: Short | None = None
    timezone: Short | None = None
    utc_offset_minutes: int | None = Field(default=None, ge=-1440, le=1440)
    boot_time: AwareDatetime | None = None


class ClockInfo(_Model):
    source: Short | None = None
    synchronized: bool | None = None
    ntp_offset_s: float | None = Field(default=None, ge=-1e9, le=1e9)


class FileEntry(_Model):
    path: str = Field(min_length=1, max_length=MAX_NAME_CHARS)
    sha256: Hex64
    size: int = Field(ge=0, le=2**63 - 1)
    category: Short | None = None
    source: Text | None = None
    collected_at: AwareDatetime | None = None

    @field_validator("path")
    @classmethod
    def _safe_path(cls, value: str) -> str:
        reason = unsafe_name_reason(value)
        if reason is not None:
            raise ValueError(f"unsafe path ({reason})")
        if value == "manifest.json":
            raise ValueError("the manifest cannot list itself")
        return value


class Problem(_Model):
    target: Text | None = None
    error: Text | None = None
    reason: Text | None = None


class TriageManifest(_Model):
    schema_id: Literal["dfirbench.triage/1"] = Field(alias="schema")
    collector: CollectorInfo
    host: HostInfo = Field(default_factory=HostInfo)
    operator: Short | None = None
    case_ref: Short | None = None
    mode: Literal["live", "offline"] | None = None
    elevated: bool | None = None
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    clock: ClockInfo | None = None
    files: list[FileEntry] = Field(max_length=MAX_LIST)
    errors: list[Problem] = Field(default_factory=list, max_length=MAX_LIST)
    skipped: list[Problem] = Field(default_factory=list, max_length=MAX_LIST)

    @model_validator(mode="after")
    def _unique_paths(self) -> TriageManifest:
        seen: set[str] = set()
        for entry in self.files:
            if entry.path in seen:
                raise ValueError(f"duplicate file path {entry.path!r}")
            seen.add(entry.path)
        return self


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ManifestError(f"duplicate JSON key {clean_text(key, 64)!r}")
        out[key] = value
    return out


def parse_manifest(data: bytes) -> tuple[TriageManifest, str]:
    """Validated manifest and the SHA-256 of its bytes; ``ManifestError`` otherwise."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest.json is too large")
    digest = hashlib.sha256(data).hexdigest()
    try:
        text = data.decode("utf-8-sig")  # PowerShell 5.1 may write a BOM
        raw = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except ManifestError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ManifestError(f"manifest.json is not valid JSON: {type(exc).__name__}") from exc
    if not isinstance(raw, dict):
        raise ManifestError("manifest.json must be a JSON object")
    try:
        return TriageManifest.model_validate(raw), digest
    except ValidationError as exc:
        errors = exc.errors()
        where = ".".join(str(p) for p in errors[0]["loc"])[:120] if errors else ""
        msg = clean_text(str(errors[0]["msg"]) if errors else "invalid", 200)
        raise ManifestError(
            f"manifest.json does not match {SCHEMA}: {where}: {msg} ({exc.error_count()} error(s))"
        ) from exc

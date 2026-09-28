"""Audit trail (guide 16.5): per-request rows from the middleware plus semantic action rows.

``audit_log`` is append-only (triggers + the app role has only SELECT/INSERT) and excluded from any
purge. Never put secrets, tokens or evidence content in ``detail``.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import AuditLog

log = structlog.stdlib.get_logger("dfirbench.audit")


def clean_ip(value: str | None) -> str | None:
    """A valid IP for the ``inet`` column, or None (test clients report e.g. 'testclient')."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


@dataclass(frozen=True)
class RequestMeta:
    """Where a request came from; passed by routers to services for semantic audit rows."""

    ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None


@dataclass(frozen=True)
class AuditRecord:
    action: str
    user_id: uuid.UUID | None = None
    ip: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    object_type: str | None = None
    object_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> AuditLog:
        return AuditLog(
            action=self.action,
            user_id=self.user_id,
            ip=clean_ip(self.ip),
            method=self.method,
            path=self.path,
            status=self.status,
            object_type=self.object_type,
            object_id=self.object_id,
            detail=self.detail,
        )


class AuditService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def record(
        self,
        action: str,
        *,
        user_id: uuid.UUID | None = None,
        meta: RequestMeta | None = None,
        object_type: str | None = None,
        object_id: object | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Add a semantic audit row to the caller's transaction (caller commits)."""
        payload = dict(detail or {})
        if meta and meta.request_id:
            payload.setdefault("request_id", meta.request_id)
        self.session.add(
            AuditRecord(
                action=action,
                user_id=user_id,
                ip=meta.ip if meta else None,
                object_type=object_type,
                object_id=str(object_id) if object_id is not None else None,
                detail=payload,
            ).to_row()
        )

    def query(
        self,
        *,
        user_id: uuid.UUID | None = None,
        action: str | None = None,
        object_type: str | None = None,
        object_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[AuditLog], int]:
        conditions = []
        if user_id is not None:
            conditions.append(AuditLog.user_id == user_id)
        if action:
            conditions.append(AuditLog.action == action)
        if object_type:
            conditions.append(AuditLog.object_type == object_type)
        if object_id:
            conditions.append(AuditLog.object_id == object_id)
        if since is not None:
            conditions.append(AuditLog.ts >= since)
        if until is not None:
            conditions.append(AuditLog.ts < until)
        total = self.session.execute(
            select(func.count()).select_from(AuditLog).where(*conditions)
        ).scalar_one()
        rows = self.session.execute(
            select(AuditLog)
            .where(*conditions)
            .order_by(AuditLog.id.desc())
            .limit(limit)
            .offset(offset)
        ).scalars()
        return list(rows), int(total)


class DbAuditSink:
    """Writes middleware records in their own short transaction. Failures are logged, not raised."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self.session_factory = session_factory

    def write(self, record: AuditRecord) -> None:
        try:
            with self.session_factory() as session, session.begin():
                session.add(record.to_row())
        except Exception as exc:  # noqa: BLE001 - auditing must never break the response
            log.error("audit_write_failed", exc_type=type(exc).__name__, action=record.action)

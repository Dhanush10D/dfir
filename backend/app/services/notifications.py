"""In-app notifications (table ``notifications``) and the in-app notification rules.

Phase 1 uses :func:`notify_admins` for integrity failures (written in the transaction that found
the failure). Phase 9 adds notifications created by the outbox fan-out according to the rules
(``settings.notification_rules``; see :mod:`app.services.outbox`), a per-user list and "read"
marks. A user only ever sees and marks their own rows; the app role may set ``read_at`` and
nothing else.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.exceptions import AppError, NotFoundError
from app.core.permissions import Permission, Principal
from app.db.models import Notification, Setting, User, UserRole
from app.services.audit import AuditService, RequestMeta
from app.services.authz import require_global
from app.services.outbox import RULES_KEY, clean_rules, load_rules

MAX_LIMIT = 200


def utcnow() -> datetime:
    return datetime.now(UTC)


def notify_admins(session: Session, kind: str, payload: dict[str, Any]) -> int:
    """Queue a notification for every active admin in the caller's transaction."""
    admin_ids = session.execute(
        select(User.id).where(User.role == UserRole.admin, User.is_active.is_(True))
    ).scalars()
    count = 0
    for admin_id in admin_ids:
        session.add(Notification(user_id=admin_id, kind=kind, payload=payload))
        count += 1
    return count


class NotificationService:
    def __init__(self, session: Session, clock: Callable[[], datetime] = utcnow) -> None:
        self.session = session
        self.clock = clock
        self.audit = AuditService(session)

    def list_mine(
        self, principal: Principal, *, unread_only: bool = False, limit: int = 50
    ) -> tuple[list[Notification], int]:
        if not 1 <= limit <= MAX_LIMIT:
            raise AppError("invalid_filter", f"'limit' must be 1-{MAX_LIMIT}.", 422)
        conds = [Notification.user_id == principal.user_id]
        if unread_only:
            conds.append(Notification.read_at.is_(None))
        rows = list(
            self.session.execute(
                select(Notification)
                .where(*conds)
                .order_by(Notification.created_at.desc(), Notification.id)
                .limit(limit)
            ).scalars()
        )
        unread = self.session.execute(
            select(func.count())
            .select_from(Notification)
            .where(Notification.user_id == principal.user_id, Notification.read_at.is_(None))
        ).scalar_one()
        self.session.commit()
        return rows, int(unread)

    def mark_read(self, principal: Principal, notification_id: uuid.UUID) -> Notification:
        row = self.session.execute(
            select(Notification)
            .where(Notification.id == notification_id, Notification.user_id == principal.user_id)
            .with_for_update()
        ).scalar_one_or_none()
        if row is None:
            self.session.rollback()
            raise NotFoundError("Notification not found.")
        if row.read_at is None:
            row.read_at = self.clock()
        self.session.commit()
        return row

    def mark_all_read(self, principal: Principal) -> int:
        done = self.session.execute(
            update(Notification)
            .where(Notification.user_id == principal.user_id, Notification.read_at.is_(None))
            .values(read_at=self.clock())
            .returning(Notification.id)
        ).all()
        self.session.commit()
        return len(done)

    # ------------------------------------------------------------------ rules (admin)

    def get_rules(self, principal: Principal) -> list[dict[str, Any]]:
        require_global(principal, Permission.USERS_MANAGE)
        rules = load_rules(self.session)
        self.session.commit()
        return rules

    def set_rules(
        self, principal: Principal, rules: list[dict[str, Any]], meta: RequestMeta
    ) -> list[dict[str, Any]]:
        require_global(principal, Permission.USERS_MANAGE)
        try:
            clean = clean_rules(rules)
        except ValueError as exc:
            raise AppError("invalid_rules", str(exc), 422) from exc
        now = self.clock()
        insert = pg_insert(Setting).values(
            key=RULES_KEY, value=clean, updated_by=principal.user_id, updated_at=now
        )
        self.session.execute(
            insert.on_conflict_do_update(
                index_elements=["key"],
                set_={"value": clean, "updated_by": principal.user_id, "updated_at": now},
            )
        )
        self.audit.record(
            "settings.notification_rules",
            user_id=principal.user_id,
            meta=meta,
            object_type="setting",
            object_id=RULES_KEY,
            detail={"rules": len(clean), "events": sorted({r["event"] for r in clean})},
        )
        self.session.commit()
        return clean

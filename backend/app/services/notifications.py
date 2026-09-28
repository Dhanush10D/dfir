"""In-app notifications (table ``notifications``). Phase 1 uses them for integrity failures."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Notification, User, UserRole


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

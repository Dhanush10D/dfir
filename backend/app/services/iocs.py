"""IocService (guide 11.4, 15.2): case IOC list, add, bulk import (CSV / JSON / STIX 2.1 subset),
deactivate. Values are normalized (``app.detection.ioc``) before storage; the (case, type, value)
UNIQUE constraint (NULLS NOT DISTINCT) deduplicates, and a re-added IOC is reactivated with the
new metadata (``ON CONFLICT DO UPDATE``). IOCs are never deleted: deactivation keeps the record
that alerts cite. Writes need ``investigate`` on an open case (``FOR SHARE`` on the case row).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import func, literal_column, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import AppError, InvalidStateError, NotFoundError
from app.core.permissions import Permission, Principal
from app.db.models import Case, CaseStatus, Ioc
from app.detection import ioc as I  # noqa: N812
from app.services.audit import AuditService, RequestMeta
from app.services.authz import load_case_access

ImportFormat = Literal["csv", "json", "stix"]
MAX_LIMIT = 1000


class IocService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings
        self.audit = AuditService(session)

    def _write_access(self, principal: Principal, case_id: uuid.UUID) -> None:
        access = load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )
        access.require(Permission.INVESTIGATE)
        status = self.session.execute(
            select(Case.status).where(Case.id == case_id).with_for_update(read=True)
        ).scalar_one()
        if status is CaseStatus.closed:
            self.session.rollback()
            raise InvalidStateError("The case is closed.")

    def list_iocs(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        *,
        ioc_type: str | None = None,
        active: bool | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[Ioc], int]:
        load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )
        if not 1 <= limit <= MAX_LIMIT or offset < 0:
            raise AppError("invalid_filter", f"'limit' must be 1-{MAX_LIMIT}.", 422)
        conds = [Ioc.case_id == case_id]
        if ioc_type:
            conds.append(Ioc.type == ioc_type)
        if active is not None:
            conds.append(Ioc.active.is_(active))
        total = self.session.execute(
            select(func.count()).select_from(Ioc).where(*conds)
        ).scalar_one()
        rows = list(
            self.session.execute(
                select(Ioc).where(*conds).order_by(Ioc.type, Ioc.value).limit(limit).offset(offset)
            ).scalars()
        )
        self.session.commit()
        return rows, int(total)

    def _upsert(
        self, case_id: uuid.UUID, item: I.ParsedIoc, user_id: uuid.UUID, default_tlp: str | None
    ) -> tuple[uuid.UUID, bool]:
        insert = pg_insert(Ioc).values(
            case_id=case_id,
            type=item.type,
            value=item.value,
            value_original=item.value_original,
            source=item.source,
            confidence=item.confidence if item.confidence is not None else 0.5,
            tlp=item.tlp or default_tlp or "amber",
            expires_at=item.expires_at,
            active=True,
            created_by=user_id,
            first_seen=func.now(),
        )
        ex = insert.excluded
        stmt: Any = insert.on_conflict_do_update(
            constraint="uq_iocs_case_id_type_value",
            set_={
                "active": True,
                "source": func.coalesce(ex["source"], Ioc.source),
                "confidence": ex["confidence"],
                "tlp": ex["tlp"],
                "expires_at": ex["expires_at"],
            },
        ).returning(Ioc.id, literal_column("(xmax = 0)").label("inserted"))
        row = self.session.execute(stmt).one()
        return row.id, bool(row.inserted)

    def create(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        meta: RequestMeta,
        *,
        ioc_type: str,
        value: str,
        source: str | None = None,
        confidence: float | None = None,
        tlp: str | None = None,
        expires_at: datetime | None = None,
    ) -> tuple[Ioc, bool]:
        self._write_access(principal, case_id)
        result = I.ImportResult([], [])
        from app.detection.ioc import parse_item  # shared validation of one item

        parse_item(
            0,
            {
                "type": ioc_type,
                "value": value,
                "source": source,
                "confidence": confidence,
                "tlp": tlp,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
            result,
        )
        if result.errors:
            self.session.rollback()
            raise AppError("invalid_ioc", result.errors[0]["error"], 422)
        ioc_id, created = self._upsert(case_id, result.items[0], principal.user_id, None)
        self.audit.record(
            "ioc.created" if created else "ioc.updated",
            user_id=principal.user_id,
            meta=meta,
            object_type="ioc",
            object_id=ioc_id,
            detail={"case_id": str(case_id), "type": result.items[0].type},
        )
        self.session.commit()
        row = self.session.execute(select(Ioc).where(Ioc.id == ioc_id)).scalar_one()
        self.session.refresh(row)
        return row, created

    def import_(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        meta: RequestMeta,
        *,
        fmt: ImportFormat,
        content: str,
        default_tlp: str | None = None,
    ) -> dict[str, Any]:
        if default_tlp is not None and default_tlp not in I.TLP:
            raise AppError("invalid_ioc", f"tlp must be one of {', '.join(I.TLP)}", 422)
        parser = {"csv": I.parse_csv, "json": I.parse_json, "stix": I.parse_stix}[fmt]
        try:
            parsed = parser(content)
        except I.IocError as exc:
            raise AppError("invalid_import", str(exc), 422) from exc
        self._write_access(principal, case_id)
        created = updated = 0
        for item in parsed.items:
            _, was_created = self._upsert(case_id, item, principal.user_id, default_tlp)
            created += was_created
            updated += not was_created
        self.audit.record(
            "ioc.imported",
            user_id=principal.user_id,
            meta=meta,
            object_type="case",
            object_id=case_id,
            detail={
                "format": fmt,
                "created": created,
                "updated": updated,
                "rejected": len(parsed.errors),
            },
        )
        self.session.commit()
        return {
            "created": created,
            "updated": updated,
            "rejected": parsed.errors[:200],
            "rejected_count": len(parsed.errors),
        }

    def deactivate(
        self, principal: Principal, case_id: uuid.UUID, ioc_id: uuid.UUID, meta: RequestMeta
    ) -> Ioc:
        self._write_access(principal, case_id)
        row = self.session.execute(
            update(Ioc)
            .where(Ioc.id == ioc_id, Ioc.case_id == case_id)
            .values(active=False)
            .returning(Ioc.id)
        ).scalar_one_or_none()
        if row is None:
            self.session.rollback()
            raise NotFoundError("IOC not found.")
        self.audit.record(
            "ioc.deactivated",
            user_id=principal.user_id,
            meta=meta,
            object_type="ioc",
            object_id=ioc_id,
            detail={"case_id": str(case_id)},
        )
        self.session.commit()
        return self.session.execute(select(Ioc).where(Ioc.id == ioc_id)).scalar_one()

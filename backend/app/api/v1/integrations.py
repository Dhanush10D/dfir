"""Integration settings, notification rules, in-app notifications (guide 15.2, 19.3, 19.4).

HTTP only. Integration endpoints need ``users:manage`` (admin). Secrets go in and never come out:
responses carry ``has_secret`` and a keyed fingerprint only.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import (
    CurrentPrincipal,
    IntegrationSvc,
    Meta,
    NotificationSvc,
    require_permission,
)
from app.core.permissions import Permission, Principal
from app.db.models import Integration
from app.schemas.integrations import (
    DeliveryLog,
    DeliveryOut,
    InboundDeliveryOut,
    IntegrationCreate,
    IntegrationList,
    IntegrationOut,
    IntegrationUpdate,
    NotificationList,
    NotificationOut,
    NotificationRule,
    NotificationRules,
    QueuedTest,
)

router = APIRouter(tags=["integrations"])

Admin = Annotated[Principal, Depends(require_permission(Permission.USERS_MANAGE))]


def _out(row: Integration) -> IntegrationOut:
    return IntegrationOut(
        id=row.id,
        type=row.type,
        name=row.name,
        enabled=row.enabled,
        config=row.config or {},
        case_id=row.case_id,
        has_secret=row.config_encrypted is not None,
        secret_fingerprint=row.secret_fingerprint if row.config_encrypted is not None else None,
        secret_key_id=row.secret_key_id,
        last_status=row.last_status,
        last_status_at=row.last_status_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("/integrations", response_model=IntegrationList)
def list_integrations(principal: Admin, integrations: IntegrationSvc) -> IntegrationList:
    rows = integrations.list_all(principal)
    return IntegrationList(
        items=[_out(r) for r in rows], secrets_available=integrations.secrets_available()
    )


@router.post("/integrations", response_model=IntegrationOut, status_code=201)
def create_integration(
    body: IntegrationCreate, principal: Admin, integrations: IntegrationSvc, meta: Meta
) -> IntegrationOut:
    row = integrations.create(
        principal,
        meta,
        kind=body.type,
        name=body.name,
        config=body.config,
        secret=body.secret,
        enabled=body.enabled,
        case_id=body.case_id,
    )
    return _out(row)


@router.get("/integrations/{integration_id}", response_model=IntegrationOut)
def get_integration(
    integration_id: uuid.UUID, principal: Admin, integrations: IntegrationSvc
) -> IntegrationOut:
    return _out(integrations.get(principal, integration_id))


@router.patch("/integrations/{integration_id}", response_model=IntegrationOut)
def update_integration(
    integration_id: uuid.UUID,
    body: IntegrationUpdate,
    principal: Admin,
    integrations: IntegrationSvc,
    meta: Meta,
) -> IntegrationOut:
    row = integrations.update(
        principal,
        integration_id,
        meta,
        name=body.name,
        config=body.config,
        secret=body.secret,
        enabled=body.enabled,
        case_id=body.case_id,
    )
    return _out(row)


@router.post("/integrations/{integration_id}/test", response_model=QueuedTest, status_code=202)
def test_integration(
    integration_id: uuid.UUID, principal: Admin, integrations: IntegrationSvc, meta: Meta
) -> QueuedTest:
    """Queue one test event for this integration; the result appears in its delivery log."""
    return QueuedTest(event_id=integrations.test(principal, integration_id, meta), queued=True)


@router.get("/integrations/{integration_id}/deliveries", response_model=DeliveryLog)
def list_deliveries(
    integration_id: uuid.UUID, principal: Admin, integrations: IntegrationSvc
) -> DeliveryLog:
    outbound, inbound = integrations.deliveries(principal, integration_id)
    return DeliveryLog(
        outbound=[DeliveryOut.model_validate(d) for d in outbound],
        inbound=[InboundDeliveryOut.model_validate(d) for d in inbound],
    )


@router.get("/settings/notification-rules", response_model=NotificationRules)
def get_notification_rules(principal: Admin, notifications: NotificationSvc) -> NotificationRules:
    rules = notifications.get_rules(principal)
    return NotificationRules(rules=[NotificationRule(**r) for r in rules])


@router.put("/settings/notification-rules", response_model=NotificationRules)
def set_notification_rules(
    body: NotificationRules, principal: Admin, notifications: NotificationSvc, meta: Meta
) -> NotificationRules:
    rules = notifications.set_rules(
        principal, [r.model_dump(mode="json") for r in body.rules], meta
    )
    return NotificationRules(rules=[NotificationRule(**r) for r in rules])


@router.get("/notifications", response_model=NotificationList)
def list_notifications(
    principal: CurrentPrincipal,
    notifications: NotificationSvc,
    unread_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> NotificationList:
    rows, unread = notifications.list_mine(principal, unread_only=unread_only, limit=limit)
    return NotificationList(items=[NotificationOut.model_validate(n) for n in rows], unread=unread)


@router.post("/notifications/read-all", status_code=204)
def read_all_notifications(principal: CurrentPrincipal, notifications: NotificationSvc) -> None:
    notifications.mark_all_read(principal)


@router.post("/notifications/{notification_id}/read", response_model=NotificationOut)
def read_notification(
    notification_id: uuid.UUID, principal: CurrentPrincipal, notifications: NotificationSvc
) -> NotificationOut:
    return NotificationOut.model_validate(notifications.mark_read(principal, notification_id))

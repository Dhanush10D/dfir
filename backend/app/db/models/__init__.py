"""All ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.db.models.ai import AiIndexState, AiInteraction, EventChunk
from app.db.models.audit import Anchor, AuditLog, SigningKey
from app.db.models.cases import Case, CaseMember
from app.db.models.collaboration import Bookmark, Note, NoteVersion, Notification, SavedQuery
from app.db.models.collection import BundleMember
from app.db.models.detection import Alert, AlertEvent, AlertHistory, Ioc, Rule, RuleVersion
from app.db.models.entities import Entity, EntityAlias, EntityLink
from app.db.models.enums import AlertStatus, CaseStatus, JobStatus, Severity, UserRole
from app.db.models.events import Event
from app.db.models.evidence import CustodyLog, Evidence
from app.db.models.jobs import Job
from app.db.models.ops import Agent, AgentTask, Integration, Playbook, PlaybookRun, Setting
from app.db.models.reports import Report
from app.db.models.response import (
    ActionRequest,
    InboundDelivery,
    IocEnrichment,
    OutboundDelivery,
    OutboundEvent,
    PlaybookRunStep,
)
from app.db.models.users import ApiKey, MfaRecoveryCode, RefreshToken, User

# Tables whose rows may never be updated, deleted or truncated (enforced by DB triggers).
APPEND_ONLY_TABLES = (
    "custody_log",
    "audit_log",
    "rule_versions",
    "alert_history",
    "note_versions",
    "bundle_members",
    "inbound_deliveries",
)

__all__ = [
    "APPEND_ONLY_TABLES",
    "ActionRequest",
    "Agent",
    "AgentTask",
    "AiIndexState",
    "AiInteraction",
    "Alert",
    "AlertEvent",
    "AlertHistory",
    "AlertStatus",
    "Anchor",
    "ApiKey",
    "AuditLog",
    "Bookmark",
    "BundleMember",
    "Case",
    "CaseMember",
    "CaseStatus",
    "CustodyLog",
    "Entity",
    "EntityAlias",
    "EntityLink",
    "Event",
    "EventChunk",
    "Evidence",
    "InboundDelivery",
    "Integration",
    "Ioc",
    "IocEnrichment",
    "Job",
    "JobStatus",
    "MfaRecoveryCode",
    "Note",
    "NoteVersion",
    "Notification",
    "OutboundDelivery",
    "OutboundEvent",
    "Playbook",
    "PlaybookRun",
    "PlaybookRunStep",
    "RefreshToken",
    "Report",
    "Rule",
    "RuleVersion",
    "SavedQuery",
    "Setting",
    "Severity",
    "SigningKey",
    "User",
    "UserRole",
]

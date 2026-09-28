"""All ORM models. Importing this package registers every table on ``Base.metadata``."""

from app.db.models.ai import AiInteraction, EventChunk
from app.db.models.audit import Anchor, AuditLog, SigningKey
from app.db.models.cases import Case, CaseMember
from app.db.models.collaboration import Bookmark, Note, Notification, SavedQuery
from app.db.models.detection import Alert, AlertEvent, Ioc, Rule
from app.db.models.entities import Entity, EntityAlias, EntityLink
from app.db.models.enums import AlertStatus, CaseStatus, JobStatus, Severity, UserRole
from app.db.models.events import Event
from app.db.models.evidence import CustodyLog, Evidence
from app.db.models.jobs import Job
from app.db.models.ops import Agent, AgentTask, Integration, Playbook, PlaybookRun, Setting
from app.db.models.reports import Report
from app.db.models.users import ApiKey, MfaRecoveryCode, RefreshToken, User

# Tables whose rows may never be updated, deleted or truncated (enforced by DB triggers).
APPEND_ONLY_TABLES = ("custody_log", "audit_log")

__all__ = [
    "APPEND_ONLY_TABLES",
    "Agent",
    "AgentTask",
    "AiInteraction",
    "Alert",
    "AlertEvent",
    "AlertStatus",
    "Anchor",
    "ApiKey",
    "AuditLog",
    "Bookmark",
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
    "Integration",
    "Ioc",
    "Job",
    "JobStatus",
    "MfaRecoveryCode",
    "Note",
    "Notification",
    "Playbook",
    "PlaybookRun",
    "RefreshToken",
    "Report",
    "Rule",
    "SavedQuery",
    "Setting",
    "Severity",
    "SigningKey",
    "User",
    "UserRole",
]

"""PostgreSQL enum types from guide 7.2."""

from __future__ import annotations

import enum

from sqlalchemy.dialects.postgresql import ENUM


class UserRole(enum.StrEnum):
    admin = "admin"
    lead = "lead"
    analyst = "analyst"
    viewer = "viewer"
    auditor = "auditor"


class CaseStatus(enum.StrEnum):
    open = "open"
    triage = "triage"
    containment = "containment"
    eradication = "eradication"
    recovery = "recovery"
    post_incident = "post_incident"
    closed = "closed"


class Severity(enum.StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class JobStatus(enum.StrEnum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    cancelled = "cancelled"
    partial = "partial"


class AlertStatus(enum.StrEnum):
    new = "new"
    triaged = "triaged"
    investigating = "investigating"
    true_positive = "true_positive"
    false_positive = "false_positive"
    closed = "closed"


def _pg_enum(py_enum: type[enum.Enum], name: str) -> ENUM:
    # create_type=False: the baseline migration creates the types explicitly.
    return ENUM(
        py_enum,
        name=name,
        values_callable=lambda e: [m.value for m in e],
        create_type=False,
    )


user_role_enum = _pg_enum(UserRole, "user_role")
case_status_enum = _pg_enum(CaseStatus, "case_status")
severity_enum = _pg_enum(Severity, "severity")
job_status_enum = _pg_enum(JobStatus, "job_status")
alert_status_enum = _pg_enum(AlertStatus, "alert_status")

"""Reports and the evidence export package (guide 18, 8.4). HTTP only; the lifecycle, QA, four-eyes
approval, signing and verification rules live in ``services/reports.py``.

Every report body served here (preview and downloads) carries a restrictive CSP with ``sandbox``,
``nosniff`` and ``no-store``; HTML previews are also shown by the UI in a sandboxed iframe.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Path, Query, Response

from app.api.dependencies import CurrentPrincipal, Meta, ReportsSvc
from app.db.models import Report
from app.reports.artifacts import ARTIFACT_TYPES, KIND_ARTIFACTS
from app.reports.model import SECTIONS
from app.reports.render_html import HTML_CSP
from app.schemas.reports import (
    ApplyAiRequest,
    DownloadFormat,
    ReportCreate,
    ReportDetail,
    ReportList,
    ReportOut,
    ReportUpdate,
    ReturnRequest,
    RevisionRequest,
    SectionDefOut,
    VerifyOut,
)
from app.services.reports import Download

router = APIRouter(tags=["reports"])


def _detail(report: Report, include_context: bool = False) -> ReportDetail:
    base = ReportOut.model_validate(report).model_dump()
    ctx = report.context or {}
    return ReportDetail(
        **base,
        sections=report.sections or {},
        findings=list(report.findings or []),
        qa=report.qa,
        signature=report.signature,
        manifest=report.manifest,
        section_defs=[
            SectionDefOut(name=s.name, title=s.title, required=s.required, ai_draft=s.ai_draft)
            for s in SECTIONS[report.kind]
        ],
        formats=[ARTIFACT_TYPES[n][0] for n in KIND_ARTIFACTS[report.kind]]
        + (["seal"] if report.status == "signed" else []),
        counts=ctx.get("counts", {}),
        truncated=ctx.get("truncated", {}),
        context=ctx if include_context else None,
    )


def _body(out: Download, *, inline: bool) -> Response:
    disposition = "inline" if inline else "attachment"
    return Response(
        content=out.data,
        media_type=out.content_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{out.filename}"',
            "Content-Security-Policy": HTML_CSP,
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "X-Content-SHA256": out.sha256,
        },
    )


@router.get("/cases/{case_id}/reports", response_model=ReportList)
def list_reports(
    case_id: uuid.UUID, principal: CurrentPrincipal, reports: ReportsSvc
) -> ReportList:
    rows = reports.list_reports(principal, case_id)
    return ReportList(items=[ReportOut.model_validate(r) for r in rows])


@router.post("/cases/{case_id}/reports", response_model=ReportDetail, status_code=201)
def create_report(
    case_id: uuid.UUID,
    body: ReportCreate,
    principal: CurrentPrincipal,
    reports: ReportsSvc,
    meta: Meta,
) -> ReportDetail:
    """Takes the data snapshot now; later case changes need a new version."""
    return _detail(reports.create(principal, case_id, meta, kind=body.kind, title=body.title))


@router.get("/reports/{report_id}", response_model=ReportDetail)
def get_report(
    report_id: uuid.UUID,
    principal: CurrentPrincipal,
    reports: ReportsSvc,
    include_context: bool = False,
) -> ReportDetail:
    report, _ = reports.get(principal, report_id)
    return _detail(report, include_context)


@router.patch("/reports/{report_id}", response_model=ReportDetail)
def update_report(
    report_id: uuid.UUID,
    body: ReportUpdate,
    principal: CurrentPrincipal,
    reports: ReportsSvc,
    meta: Meta,
) -> ReportDetail:
    report = reports.update(
        principal,
        report_id,
        meta,
        expected_revision=body.expected_revision,
        title=body.title,
        sections=body.sections,
        findings=[f.model_dump(mode="json") for f in body.findings]
        if body.findings is not None
        else None,
    )
    return _detail(report)


@router.post("/reports/{report_id}/qa", response_model=ReportDetail)
def run_qa(
    report_id: uuid.UUID, principal: CurrentPrincipal, reports: ReportsSvc, meta: Meta
) -> ReportDetail:
    return _detail(reports.run_qa(principal, report_id, meta))


@router.post("/reports/{report_id}/submit", response_model=ReportDetail)
def submit_report(
    report_id: uuid.UUID,
    body: RevisionRequest,
    principal: CurrentPrincipal,
    reports: ReportsSvc,
    meta: Meta,
) -> ReportDetail:
    report = reports.submit(principal, report_id, meta, expected_revision=body.expected_revision)
    return _detail(report)


@router.post("/reports/{report_id}/return", response_model=ReportDetail)
def return_report(
    report_id: uuid.UUID,
    body: ReturnRequest,
    principal: CurrentPrincipal,
    reports: ReportsSvc,
    meta: Meta,
) -> ReportDetail:
    return _detail(reports.return_to_draft(principal, report_id, meta, reason=body.reason))


@router.post("/reports/{report_id}/approve", response_model=ReportDetail)
def approve_report(
    report_id: uuid.UUID, principal: CurrentPrincipal, reports: ReportsSvc, meta: Meta
) -> ReportDetail:
    return _detail(reports.approve(principal, report_id, meta))


@router.post("/reports/{report_id}/sign", response_model=ReportDetail)
def sign_report(
    report_id: uuid.UUID, principal: CurrentPrincipal, reports: ReportsSvc, meta: Meta
) -> ReportDetail:
    return _detail(reports.sign(principal, report_id, meta))


@router.post("/reports/{report_id}/versions", response_model=ReportDetail, status_code=201)
def new_version(
    report_id: uuid.UUID, principal: CurrentPrincipal, reports: ReportsSvc, meta: Meta
) -> ReportDetail:
    """A new draft version with a fresh snapshot; sections and findings are copied."""
    return _detail(reports.new_version(principal, report_id, meta))


@router.post("/reports/{report_id}/sections/{section}/apply-ai", response_model=ReportDetail)
def apply_ai_draft(
    report_id: uuid.UUID,
    section: Annotated[str, Path(max_length=64, pattern="^[a-z_]+$")],
    body: ApplyAiRequest,
    principal: CurrentPrincipal,
    reports: ReportsSvc,
    meta: Meta,
) -> ReportDetail:
    report = reports.apply_ai(
        principal,
        report_id,
        section,
        meta,
        interaction_id=body.interaction_id,
        expected_revision=body.expected_revision,
    )
    return _detail(report)


@router.get("/reports/{report_id}/verify", response_model=VerifyOut)
def verify_report(
    report_id: uuid.UUID, principal: CurrentPrincipal, reports: ReportsSvc, meta: Meta
) -> VerifyOut:
    return VerifyOut(**reports.verify(principal, report_id, meta))


@router.get("/reports/{report_id}/preview")
def preview_report(
    report_id: uuid.UUID, principal: CurrentPrincipal, reports: ReportsSvc, meta: Meta
) -> Response:
    """The HTML rendering (drafts are rendered now and marked DRAFT; signed ones are stored)."""
    return _body(reports.download(principal, report_id, meta, fmt="html"), inline=True)


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: uuid.UUID,
    principal: CurrentPrincipal,
    reports: ReportsSvc,
    meta: Meta,
    format: Annotated[DownloadFormat, Query()] = "pdf",
) -> Response:
    return _body(reports.download(principal, report_id, meta, fmt=format), inline=False)


@router.post("/evidence/{evidence_id}/export-package", tags=["evidence"])
def export_package(
    evidence_id: uuid.UUID, principal: CurrentPrincipal, reports: ReportsSvc, meta: Meta
) -> Response:
    """Signed evidence package (manifest, custody chain, signature); appends ``exported``."""
    out = reports.export_package(principal, evidence_id, meta)
    return Response(
        content=out.data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{out.filename}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "X-Content-SHA256": out.sha256,
            "X-Custody-Seq": str(out.custody_seq),
        },
    )

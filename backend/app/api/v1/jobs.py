"""Processing jobs (guide 15.2 "Jobs"): submit, list, detail with run manifest, cancel, retry,
reprocess. HTTP only; logic and authorization in services/jobs.py."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, status

from app.api.dependencies import CurrentPrincipal, Jobs, Meta
from app.db.models import Job, JobStatus
from app.schemas.jobs import (
    JobDetail,
    JobList,
    JobOut,
    ParserOut,
    ProcessOut,
    ProcessRequest,
    ReprocessRequest,
)
from app.services.jobs import PARSER_PARAMS

router = APIRouter(tags=["jobs"])


def _counts(job: Job) -> dict[str, int] | None:
    manifest = job.run_manifest or {}
    counts = manifest.get("counts")
    if not isinstance(counts, dict):
        return None
    return {k: v for k, v in counts.items() if isinstance(v, int)}


def job_out(job: Job) -> JobOut:
    return JobOut.model_validate(job).model_copy(update={"counts": _counts(job)})


def job_detail(job: Job) -> JobDetail:
    return JobDetail.model_validate(job).model_copy(update={"counts": _counts(job)})


@router.get("/parsers", response_model=list[ParserOut])
def list_parsers(principal: CurrentPrincipal, jobs: Jobs) -> list[ParserOut]:
    return [
        ParserOut(
            name=p.name,
            version=p.version,
            description=p.description,
            source_types=list(p.source_types),
            params=sorted(PARSER_PARAMS.get(p.name, frozenset())),
        )
        for p in jobs.parsers()
    ]


@router.post(
    "/evidence/{evidence_id}/process",
    response_model=ProcessOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def process_evidence(
    evidence_id: uuid.UUID,
    body: ProcessRequest,
    principal: CurrentPrincipal,
    jobs: Jobs,
    meta: Meta,
) -> ProcessOut:
    """Queue parser jobs. The same evidence/parser/version/params returns the existing job."""
    results = jobs.submit(
        principal,
        evidence_id,
        parsers=None if body.parsers == "auto" else list(body.parsers),
        params=body.params.model_dump(),
        meta=meta,
    )
    return ProcessOut(
        jobs=[job_out(r.job) for r in results],
        created=[r.job.id for r in results if r.created],
    )


@router.get("/cases/{case_id}/jobs", response_model=JobList)
def list_jobs(
    case_id: uuid.UUID,
    principal: CurrentPrincipal,
    jobs: Jobs,
    status_filter: Annotated[JobStatus | None, Query(alias="status")] = None,
    evidence_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> JobList:
    rows = jobs.list_for_case(
        principal, case_id, status=status_filter, evidence_id=evidence_id, limit=limit
    )
    return JobList(items=[job_out(j) for j in rows])


@router.get("/jobs/{job_id}", response_model=JobDetail)
def get_job(job_id: uuid.UUID, principal: CurrentPrincipal, jobs: Jobs) -> JobDetail:
    return job_detail(jobs.get(principal, job_id))


@router.post("/jobs/{job_id}/cancel", response_model=JobDetail)
def cancel_job(job_id: uuid.UUID, principal: CurrentPrincipal, jobs: Jobs, meta: Meta) -> JobDetail:
    return job_detail(jobs.cancel(principal, job_id, meta))


@router.post("/jobs/{job_id}/retry", response_model=JobDetail, status_code=202)
def retry_job(job_id: uuid.UUID, principal: CurrentPrincipal, jobs: Jobs, meta: Meta) -> JobDetail:
    return job_detail(jobs.retry(principal, job_id, meta))


@router.post("/jobs/{job_id}/reprocess", response_model=JobDetail, status_code=202)
def reprocess_job(
    job_id: uuid.UUID,
    principal: CurrentPrincipal,
    jobs: Jobs,
    meta: Meta,
    body: ReprocessRequest | None = None,
) -> JobDetail:
    """New run with the parser's current version; its events replace the previous run's."""
    params = body.params.model_dump() if body and body.params else None
    return job_detail(jobs.reprocess(principal, job_id, meta, params))

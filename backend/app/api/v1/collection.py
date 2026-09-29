"""Triage bundle ingest results (Phase 5). HTTP only; logic in services/bundles.py.

Ingest itself is started with ``POST /evidence/{id}/process`` on a ``triage_bundle`` item.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Query

from app.api.dependencies import Bundles, CurrentPrincipal
from app.api.v1.jobs import job_out
from app.schemas.collection import BundleMemberOut, BundleSummaryOut, DerivedEvidenceOut

router = APIRouter(tags=["collection"])


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


@router.get("/evidence/{evidence_id}/bundle", response_model=BundleSummaryOut)
def bundle_summary(
    evidence_id: uuid.UUID,
    principal: CurrentPrincipal,
    bundles: Bundles,
    limit: Annotated[int, Query(ge=1, le=10000)] = 1000,
) -> BundleSummaryOut:
    """Latest ingest run of a triage bundle: collector, trust, member verdicts, derived items."""
    summary = bundles.summary(principal, evidence_id, limit)
    manifest: dict[str, Any] = (summary.job.run_manifest or {}) if summary.job else {}
    info = _dict(manifest.get("bundle"))
    counts = _dict(manifest.get("counts"))
    rejected = manifest.get("rejected")
    rejected = rejected if isinstance(rejected, list) else []
    return BundleSummaryOut(
        evidence_id=summary.evidence.id,
        job=job_out(summary.job) if summary.job else None,
        outcome=manifest.get("outcome"),
        collector=info.get("collector"),
        collector_trust=info.get("collector_trust"),
        host=info.get("host"),
        manifest_sha256=info.get("manifest_sha256"),
        counts={k: v for k, v in counts.items() if isinstance(v, int)},
        rejected=rejected,
        members=[BundleMemberOut.model_validate(m) for m in summary.members],
        derived=[DerivedEvidenceOut.model_validate(e) for e in summary.derived],
    )

"""Evidence and custody endpoints (guide 15.2). HTTP only; logic in services/evidence.py.

The upload is a raw ``PUT`` whose body is streamed chunk by chunk from the ASGI server through the
hashing reader into the vault (S3 multipart), so memory stays bounded by one part.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from functools import partial

import anyio
import anyio.from_thread
from fastapi import APIRouter, Request, status
from fastapi.responses import StreamingResponse

from app.api.dependencies import CurrentPrincipal, CustodySvc, EvidenceSvc, Meta
from app.core.exceptions import AppError
from app.schemas.evidence import (
    ChainReportOut,
    CustodyChainOut,
    CustodyEntryOut,
    EvidenceCreate,
    EvidenceCreated,
    EvidenceList,
    EvidenceOut,
    FinalizeOut,
    SigningKeyOut,
    UploadSession,
    VerifyOut,
)

router = APIRouter(tags=["evidence"])

API = "/api/v1"


class BlockingBodyReader:
    """Synchronous ``read(n)`` over an async request body, for use from a worker thread.

    Buffers at most ``n`` bytes plus one incoming ASGI chunk.
    """

    def __init__(self, stream: AsyncIterator[bytes]) -> None:
        self._iterator = stream.__aiter__()
        self._buffer = bytearray()
        self._eof = False

    async def _next(self) -> bytes | None:
        try:
            return await self._iterator.__anext__()
        except StopAsyncIteration:
            return None

    def read(self, size: int = -1, /) -> bytes:
        if size < 0:
            raise ValueError("unbounded reads are not supported (stream in parts)")
        while not self._eof and len(self._buffer) < size:
            chunk = anyio.from_thread.run(self._next)
            if chunk is None:
                self._eof = True
                break
            self._buffer.extend(chunk)
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data


@router.post(
    "/cases/{case_id}/evidence",
    response_model=EvidenceCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_evidence(
    case_id: uuid.UUID,
    body: EvidenceCreate,
    principal: CurrentPrincipal,
    svc: EvidenceSvc,
    meta: Meta,
) -> EvidenceCreated:
    ev = svc.create(principal, case_id, meta=meta, **body.model_dump())
    return EvidenceCreated(
        evidence=EvidenceOut.model_validate(ev),
        upload=UploadSession(
            url=f"{API}/evidence/{ev.id}/upload",
            max_bytes=svc.settings.max_upload_bytes,
            finalize_url=f"{API}/evidence/{ev.id}/finalize",
        ),
    )


@router.get("/cases/{case_id}/evidence", response_model=EvidenceList)
def list_evidence(
    case_id: uuid.UUID, principal: CurrentPrincipal, svc: EvidenceSvc
) -> EvidenceList:
    rows = svc.list_for_case(principal, case_id)
    return EvidenceList(items=[EvidenceOut.model_validate(e) for e in rows], total=len(rows))


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
def get_evidence(
    evidence_id: uuid.UUID, principal: CurrentPrincipal, svc: EvidenceSvc
) -> EvidenceOut:
    return EvidenceOut.model_validate(svc.get(principal, evidence_id))


@router.put(
    "/evidence/{evidence_id}/upload",
    response_model=EvidenceOut,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
            },
        }
    },
)
async def upload_evidence(
    evidence_id: uuid.UUID,
    request: Request,
    principal: CurrentPrincipal,
    svc: EvidenceSvc,
    meta: Meta,
) -> EvidenceOut:
    content_type = request.headers.get("content-type", "application/octet-stream")
    if content_type.split(";")[0].strip().lower().startswith("multipart/"):
        raise AppError(
            "unsupported_media_type", "Send the raw file bytes (application/octet-stream).", 415
        )
    raw_length = request.headers.get("content-length")
    declared = int(raw_length) if raw_length and raw_length.isdigit() else None
    reader = BlockingBodyReader(request.stream())
    ev = await anyio.to_thread.run_sync(
        partial(
            svc.receive_upload,
            principal,
            evidence_id,
            reader,
            meta=meta,
            content_type=content_type,
            declared_length=declared,
        )
    )
    return EvidenceOut.model_validate(ev)


@router.post("/evidence/{evidence_id}/finalize", response_model=FinalizeOut)
def finalize_evidence(
    evidence_id: uuid.UUID, principal: CurrentPrincipal, svc: EvidenceSvc, meta: Meta
) -> FinalizeOut:
    result = svc.finalize(principal, evidence_id, meta)
    return FinalizeOut(
        ok=result.ok,
        evidence=EvidenceOut.model_validate(result.evidence),
        computed=result.digests.as_dict(),
        mismatches=result.mismatches,
        retention_mode=result.retention.mode if result.retention else None,
        retain_until=result.retention.retain_until if result.retention else None,
    )


@router.post("/evidence/{evidence_id}/verify", response_model=VerifyOut)
def verify_evidence(
    evidence_id: uuid.UUID, principal: CurrentPrincipal, svc: EvidenceSvc, meta: Meta
) -> VerifyOut:
    """Re-hash the stored object, validate the custody chain and signatures (guide 8.3 rule 5)."""
    result = svc.verify(principal, evidence_id, meta)
    return VerifyOut(
        ok=result.ok,
        status="verified" if result.ok else "integrity_failure",
        evidence_id=result.evidence.id,
        evidence_status=result.evidence.status,
        verified_at=result.verified_at,
        object=result.object_check.as_dict(),
        chain=ChainReportOut.model_validate(result.chain.as_dict()),
        custody_entry=CustodyEntryOut.model_validate(result.custody_entry),
    )


@router.get("/evidence/{evidence_id}/custody", response_model=CustodyChainOut)
def custody_chain(
    evidence_id: uuid.UUID, principal: CurrentPrincipal, svc: EvidenceSvc
) -> CustodyChainOut:
    rows = svc.custody_entries(principal, evidence_id)
    return CustodyChainOut(
        evidence_id=evidence_id, entries=[CustodyEntryOut.model_validate(r) for r in rows]
    )


@router.get(
    "/evidence/{evidence_id}/download",
    response_class=StreamingResponse,
    responses={200: {"content": {"application/octet-stream": {}}}},
)
def download_evidence(
    evidence_id: uuid.UUID, principal: CurrentPrincipal, svc: EvidenceSvc, meta: Meta
) -> StreamingResponse:
    """Audited download of the original bytes (writes a ``downloaded`` custody entry first)."""
    handle = svc.download(principal, evidence_id, meta)
    headers = {"Content-Disposition": f'attachment; filename="{handle.filename}"'}
    if handle.sha256:
        headers["X-Evidence-SHA256"] = handle.sha256
    if handle.size is not None:
        headers["Content-Length"] = str(handle.size)
    return StreamingResponse(handle.chunks, media_type=handle.mime_type, headers=headers)


@router.get("/signing-keys", response_model=list[SigningKeyOut], tags=["custody"])
def signing_keys(principal: CurrentPrincipal, custody: CustodySvc) -> list[SigningKeyOut]:
    """Published custody public keys, so anyone can verify exported chains independently."""
    return [SigningKeyOut.model_validate(r) for r in custody.list_signing_keys()]

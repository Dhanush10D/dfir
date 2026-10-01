"""Indicator enrichment for case IOCs (guide 19.3): VirusTotal and MISP, mockable.

* Off unless ``ENABLE_ENRICHMENT`` is set **and** the provider's integration is enabled (both
  default to off). ``ENRICHMENT_FAKE`` swaps every provider for the deterministic offline fake.
* Only the indicator value (hash, IP, domain, URL) is sent. TLP decides where it may go
  (:func:`app.integrations.enrichment.tlp_allows`); what is held back is reported, not sent.
* Results are cached per (provider, type, value) for ``ENRICHMENT_CACHE_TTL_H``; a fresh cache
  row is returned without any request.
* No transaction or lock is held while a provider is called: the case is checked, the IOCs are
  read, the transaction ends; after the lookups the case is locked ``FOR SHARE`` and re-checked
  (it may have been closed meanwhile) before the cache rows and the audit row are written.
* The audit row holds counts and provider names, never indicator values.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import AppError, InvalidStateError, NotFoundError
from app.core.permissions import Permission, Principal
from app.db.models import Case, CaseStatus, Integration, Ioc, IocEnrichment
from app.integrations.crypto import (
    Keyring,
    SealedSecret,
    SecretDecryptError,
    SecretsUnavailableError,
    integration_aad,
)
from app.integrations.enrichment import (
    ENRICHABLE_TYPES,
    VIRUSTOTAL_MAX_TLP,
    VIRUSTOTAL_URL,
    EnrichmentError,
    EnrichmentProvider,
    FakeEnrichmentProvider,
    Indicator,
    MispProvider,
    Verdict,
    VirusTotalProvider,
    tlp_allows,
)
from app.integrations.outbound import OutboundHttp, OutboundPolicy
from app.services.audit import AuditService, RequestMeta
from app.services.authz import CaseAccess, load_case_access

log = structlog.stdlib.get_logger("dfirbench.enrichment")

PROVIDER_TYPES = ("virustotal", "misp")
DEADLINE_S = 45.0
ProviderFactory = Callable[[Integration, dict[str, Any]], EnrichmentProvider]


def utcnow() -> datetime:
    return datetime.now(UTC)


def value_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class EnrichmentService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        http: OutboundHttp | None = None,
        keyring: Keyring | None = None,
        provider_factory: ProviderFactory | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.session = session
        self.settings = settings
        self.http = http or OutboundHttp(OutboundPolicy.from_settings(settings))
        self._keyring = keyring
        self.provider_factory = provider_factory or self._build_provider
        self.clock = clock
        self.audit = AuditService(session)

    # ------------------------------------------------------------------ providers

    def _build_provider(self, integ: Integration, secret: dict[str, Any]) -> EnrichmentProvider:
        config = integ.config or {}
        max_tlp = (
            VIRUSTOTAL_MAX_TLP
            if integ.type == "virustotal"
            else str(config.get("max_tlp", "green"))
        )
        if self.settings.enrichment_fake:
            return FakeEnrichmentProvider(name=integ.type, max_tlp=max_tlp)
        key = str(secret.get("api_key") or "")
        if not key:
            raise EnrichmentError("secret_unavailable")
        if integ.type == "virustotal":
            return VirusTotalProvider(self.http, key, str(config.get("base_url") or VIRUSTOTAL_URL))
        return MispProvider(self.http, key, str(config.get("url") or ""), max_tlp)

    def _secret(self, integ: Integration) -> dict[str, Any]:
        if self.settings.enrichment_fake:
            return {}
        if (
            integ.config_encrypted is None
            or not integ.secret_wrapped_key
            or not integ.secret_key_id
        ):
            return {}
        try:
            if self._keyring is None:
                self._keyring = Keyring.from_settings(self.settings)
            sealed = SealedSecret(
                bytes(integ.config_encrypted), bytes(integ.secret_wrapped_key), integ.secret_key_id
            )
            return self._keyring.open(sealed, integration_aad(integ.id))
        except (SecretsUnavailableError, SecretDecryptError):
            log.error("enrichment_secret_unavailable", integration_id=str(integ.id))
            return {}

    def _providers(self, only: Sequence[str] | None = None) -> list[EnrichmentProvider]:
        if not self.settings.enable_enrichment:
            raise AppError(
                "enrichment_disabled",
                "Enrichment is switched off (ENABLE_ENRICHMENT); no indicator leaves the platform.",
                409,
            )
        rows = self.session.execute(
            select(Integration)
            .where(Integration.type.in_(PROVIDER_TYPES), Integration.enabled.is_(True))
            .order_by(Integration.type, Integration.name)
        ).scalars()
        providers: list[EnrichmentProvider] = []
        seen: set[str] = set()
        for row in rows:
            if row.type in seen or (only and row.type not in only):
                continue  # one integration per provider type
            try:
                providers.append(self.provider_factory(row, self._secret(row)))
            except (EnrichmentError, ValueError):
                log.warning("enrichment_provider_unusable", integration_id=str(row.id))
                continue
            seen.add(row.type)
        if not providers:
            raise AppError(
                "no_enrichment_provider", "No enrichment provider is enabled and usable.", 409
            )
        return providers

    # ------------------------------------------------------------------ access

    def _access(self, principal: Principal, case_id: uuid.UUID) -> CaseAccess:
        return load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )

    def _lock_open_case(self, case_id: uuid.UUID) -> None:
        status = self.session.execute(
            select(Case.status).where(Case.id == case_id).with_for_update(read=True)
        ).scalar_one()
        if status is CaseStatus.closed:
            self.session.rollback()
            raise InvalidStateError("The case is closed.")

    def _cached(self, provider: str, ioc: Ioc) -> IocEnrichment | None:
        return self.session.execute(
            select(IocEnrichment).where(
                IocEnrichment.provider == provider,
                IocEnrichment.ioc_type == ioc.type,
                IocEnrichment.value_sha256 == value_sha256(ioc.value),
            )
        ).scalar_one_or_none()

    @staticmethod
    def _entry(ioc: Ioc, provider: str, status: str, **extra: Any) -> dict[str, Any]:
        return {"ioc_id": str(ioc.id), "provider": provider, "status": status, **extra}

    @staticmethod
    def _verdict_fields(row: IocEnrichment) -> dict[str, Any]:
        return {
            "verdict": row.verdict,
            "score": row.score,
            "summary": row.summary,
            "fetched_at": row.fetched_at,
            "expires_at": row.expires_at,
        }

    # ------------------------------------------------------------------ enrich

    def enrich(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        meta: RequestMeta,
        *,
        ioc_ids: Sequence[uuid.UUID] | None = None,
        providers: Sequence[str] | None = None,
        refresh: bool = False,
    ) -> dict[str, Any]:
        self._access(principal, case_id).require(Permission.INVESTIGATE)
        self._lock_open_case(case_id)
        active = self._providers(providers)
        conds = [Ioc.case_id == case_id, Ioc.active.is_(True), Ioc.type.in_(ENRICHABLE_TYPES)]
        if ioc_ids:
            conds.append(Ioc.id.in_(list(ioc_ids)))
        cap = self.settings.enrichment_max_per_request
        iocs = list(
            self.session.execute(
                select(Ioc).where(*conds).order_by(Ioc.type, Ioc.value).limit(cap + 1)
            ).scalars()
        )
        truncated = len(iocs) > cap
        iocs = iocs[:cap]
        now = self.clock()
        results: list[dict[str, Any]] = []
        todo: list[tuple[Ioc, EnrichmentProvider]] = []
        for ioc in iocs:
            for provider in active:
                if not provider.supports(ioc.type):
                    continue
                if not tlp_allows(provider.max_tlp, ioc.tlp):
                    results.append(
                        self._entry(ioc, provider.name, "skipped_tlp", tlp=ioc.tlp or "amber")
                    )
                    continue
                cached = self._cached(provider.name, ioc)
                if cached is not None and cached.expires_at > now and not refresh:
                    results.append(
                        self._entry(ioc, provider.name, "cached", **self._verdict_fields(cached))
                    )
                    continue
                todo.append((ioc, provider))
        self.session.commit()  # no lock and no transaction while providers are called

        fetched: list[tuple[Ioc, str, Verdict]] = []
        deadline = time.monotonic() + DEADLINE_S
        for ioc, provider in todo:
            if time.monotonic() > deadline:
                results.append(self._entry(ioc, provider.name, "skipped_deadline"))
                continue
            try:
                verdict = provider.lookup(Indicator(ioc.type, ioc.value))
            except EnrichmentError as exc:
                results.append(self._entry(ioc, provider.name, "error", error=exc.category))
                continue
            fetched.append((ioc, provider.name, verdict))

        self._lock_open_case(case_id)  # re-check: the case may have been closed meanwhile
        now = self.clock()
        expires = now + timedelta(hours=self.settings.enrichment_cache_ttl_h)
        for ioc, name, verdict in fetched:
            insert = pg_insert(IocEnrichment).values(
                id=uuid.uuid4(),
                provider=name,
                ioc_type=ioc.type,
                value_sha256=value_sha256(ioc.value),
                value=ioc.value,
                verdict=verdict.verdict,
                score=verdict.score,
                summary=verdict.summary,
                fetched_at=now,
                expires_at=expires,
            )
            ex = insert.excluded
            self.session.execute(
                insert.on_conflict_do_update(
                    constraint="uq_ioc_enrichments_provider_ioc_type_value_sha256",
                    set_={
                        "verdict": ex["verdict"],
                        "score": ex["score"],
                        "summary": ex["summary"],
                        "fetched_at": ex["fetched_at"],
                        "expires_at": ex["expires_at"],
                    },
                )
            )
            results.append(
                self._entry(
                    ioc,
                    name,
                    "fetched",
                    verdict=verdict.verdict,
                    score=verdict.score,
                    summary=verdict.summary,
                    fetched_at=now,
                    expires_at=expires,
                )
            )
        counts: dict[str, int] = {}
        for entry in results:
            counts[entry["status"]] = counts.get(entry["status"], 0) + 1
        self.audit.record(
            "ioc.enriched",
            user_id=principal.user_id,
            meta=meta,
            object_type="case",
            object_id=case_id,
            detail={
                "providers": [p.name for p in active],
                "iocs": len(iocs),
                "counts": counts,
                "truncated": truncated,
                "fake": self.settings.enrichment_fake,
            },
        )
        self.session.commit()
        results.sort(key=lambda e: (e["ioc_id"], e["provider"]))
        return {"results": results, "counts": counts, "truncated": truncated}

    def list_cached(self, principal: Principal, case_id: uuid.UUID) -> list[dict[str, Any]]:
        """Cached verdicts for the case's IOCs (no provider is called)."""
        self._access(principal, case_id).require(Permission.CASE_READ)
        now = self.clock()
        rows = self.session.execute(
            select(Ioc, IocEnrichment)
            .join(
                IocEnrichment,
                (IocEnrichment.ioc_type == Ioc.type) & (IocEnrichment.value == Ioc.value),
            )
            .where(Ioc.case_id == case_id)
            .order_by(Ioc.type, Ioc.value, IocEnrichment.provider)
            .limit(2000)
        ).all()
        out = [
            self._entry(
                ioc,
                row.provider,
                "cached" if row.expires_at > now else "stale",
                **self._verdict_fields(row),
            )
            for ioc, row in rows
        ]
        self.session.commit()
        return out

    # ------------------------------------------------------------------ sightings

    def export_sighting(
        self, principal: Principal, case_id: uuid.UUID, ioc_id: uuid.UUID, meta: RequestMeta
    ) -> dict[str, Any]:
        """Report to MISP that the indicator was seen (only within its TLP)."""
        self._access(principal, case_id).require(Permission.INVESTIGATE)
        self._lock_open_case(case_id)
        ioc = self.session.execute(
            select(Ioc).where(Ioc.id == ioc_id, Ioc.case_id == case_id)
        ).scalar_one_or_none()
        if ioc is None:
            self.session.rollback()
            raise NotFoundError("IOC not found.")
        provider = self._providers(["misp"])[0]
        if ioc.type not in ENRICHABLE_TYPES or not tlp_allows(provider.max_tlp, ioc.tlp):
            self.session.rollback()
            raise AppError(
                "tlp_restricted",
                "This indicator's TLP does not allow it to be shared with the provider.",
                409,
                {"tlp": ioc.tlp or "amber", "max_tlp": provider.max_tlp},
            )
        self.session.commit()
        now = self.clock()
        try:
            provider.add_sighting(Indicator(ioc.type, ioc.value), now)
        except EnrichmentError as exc:
            raise AppError(
                "enrichment_failed", "The provider did not accept the sighting.", 502,
                {"error": exc.category},
            ) from exc  # fmt: skip
        self._lock_open_case(case_id)
        self.audit.record(
            "ioc.sighting_exported",
            user_id=principal.user_id,
            meta=meta,
            object_type="ioc",
            object_id=ioc_id,
            detail={
                "case_id": str(case_id),
                "provider": provider.name,
                "type": ioc.type,
                "tlp": ioc.tlp,
                "fake": self.settings.enrichment_fake,
            },
        )
        self.session.commit()
        return {"ioc_id": str(ioc_id), "provider": provider.name, "exported": True}

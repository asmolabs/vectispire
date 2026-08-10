import logging
import time
from typing import Dict, List, Set

import httpx
from sqlalchemy.orm import Session

from zanshin.models.finding import Finding
from zanshin.services.settings_service import SettingsService

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Stored in the generic `setting` key/value table (see SettingsService).
SETTING_KEY_ENRICHMENT_ENABLED = "enrichment_enabled"

KEV_CACHE_TTL_SECONDS = 24 * 60 * 60
EPSS_BATCH_SIZE = 90  # stay well under the API's documented per-request limit
HTTP_TIMEOUT_SECONDS = 10.0

class EnrichmentService:
    """Best-effort, post-scan enrichment of vulnerability `Finding` rows with
    EPSS (exploit prediction) scores and CISA KEV (known-exploited) status.

    The first "cloud API" backend (décision 0001): both EPSS and CISA KEV are
    free, public, metadata-only endpoints — only bare CVE ids are sent, never
    source code or SBOM content — so there is no confidentiality trade-off
    like there would be for a SAST/secrets cloud backend (see docs/architecture/03).
    Any network failure here is logged and swallowed: a scan that already produced
    valid results must never be marked "failed" because an optional enrichment call
    didn't succeed.

    The KEV catalog (a few thousand entries) is cached at the *class* level,
    not the instance level: `IoCContainer` — and therefore this service — is
    re-instantiated on essentially every request (see `get_container()`), so
    an instance-level cache would never actually be reused. A class-level
    cache still gets the benefit within a single running process.
    """

    _kev_cache: Set[str] = set()
    _kev_cache_fetched_at: float = 0.0

    def __init__(self, settings_service: SettingsService, http_get=httpx.get):
        self.settings_service = settings_service
        # Injectable for tests; defaults to a plain one-off call per request
        # rather than a long-lived httpx.Client, since this service itself
        # is recreated on every request — a persistent client here would
        # leak connections over the app's lifetime.
        self._http_get = http_get

    def is_enabled(self) -> bool:
        return self.settings_service.get_setting(SETTING_KEY_ENRICHMENT_ENABLED, "true") == "true"

    def enrich_findings(self, db: Session, findings: List[Finding]) -> None:
        """Populate `epss_score`/`is_kev` on vulnerability findings and commit."""
        if not self.is_enabled():
            return

        vuln_findings = [f for f in findings if f.type == "vulnerability" and f.identifier]
        if not vuln_findings:
            return

        cve_ids = sorted({f.identifier for f in vuln_findings})
        epss_scores = self._fetch_epss_scores(cve_ids)
        kev_ids = self._get_kev_ids()

        for finding in vuln_findings:
            if finding.identifier in epss_scores:
                finding.epss_score = epss_scores[finding.identifier]
            finding.is_kev = finding.identifier in kev_ids

        db.commit()
        logger.info(
            "Enrichment: %d/%d CVE(s) matched an EPSS score, %d flagged as CISA KEV",
            len(epss_scores), len(cve_ids), sum(1 for f in vuln_findings if f.is_kev)
        )

    def _fetch_epss_scores(self, cve_ids: List[str]) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
            batch = cve_ids[i:i + EPSS_BATCH_SIZE]
            try:
                response = self._http_get(
                    EPSS_API_URL,
                    params={"cve": ",".join(batch)},
                    timeout=HTTP_TIMEOUT_SECONDS,
                )
                response.raise_for_status()
                for entry in response.json().get("data", []):
                    cve = entry.get("cve")
                    epss = entry.get("epss")
                    if not cve or epss is None:
                        continue
                    try:
                        scores[cve] = float(epss)
                    except (TypeError, ValueError):
                        continue
            except Exception:
                logger.exception("EPSS lookup failed for a batch of %d CVE(s) — skipping", len(batch))
        return scores

    def _get_kev_ids(self) -> Set[str]:
        now = time.time()
        if EnrichmentService._kev_cache and (now - EnrichmentService._kev_cache_fetched_at) < KEV_CACHE_TTL_SECONDS:
            return EnrichmentService._kev_cache

        try:
            response = self._http_get(KEV_CATALOG_URL, timeout=HTTP_TIMEOUT_SECONDS)
            response.raise_for_status()
            EnrichmentService._kev_cache = {
                v.get("cveID") for v in response.json().get("vulnerabilities", []) if v.get("cveID")
            }
            EnrichmentService._kev_cache_fetched_at = now
        except Exception:
            logger.exception("CISA KEV catalog fetch failed — reusing previous cache (possibly empty)")

        return EnrichmentService._kev_cache

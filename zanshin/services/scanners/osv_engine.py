import logging
from typing import Any, Dict, List, Optional

import httpx

from zanshin.services.scanners.base import ScannerEngine
from zanshin.services.scanners.docker_engine import DockerScannerEngine

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 10.0

# OSV doesn't expose a normalized severity bucket the way Grype does; the
# closest widely-populated field is `database_specific.severity` (used by
# GHSA-sourced entries). Anything else falls back to "unknown" — which the
# existing summarizer/UI already handle as a bucket, rather than guessing by
# parsing CVSS vector strings (would need an extra dependency for little
# gain in a first cut).
_OSV_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
}

class OsvScannerEngine(ScannerEngine):
    """A "cloud API" SCA backend, as described in ADR-001 (section 3,
    option C / Phase 5): vulnerability *matching* is delegated to OSV.dev
    (a free, public vulnerability database) instead of running Grype
    locally. SBOM generation and secrets scanning stay local — Syft needs
    filesystem/image access to produce a component list in the first place,
    and there's no meaningful "send it to the cloud" alternative short of
    uploading the whole codebase/image, which defeats the point. Delegated
    to an inner `DockerScannerEngine` by default (composition, not
    inheritance, so a future local-API backend — ADR-001 Phase 4 — can be
    plugged in here instead without changing this class).

    Only bare package identifiers (purl + version, already produced by the
    local SBOM step) are sent to OSV.dev — never source code or the full
    SBOM. Selected via the `scan_backend=osv` setting.
    """

    def __init__(self, local_engine: Optional[ScannerEngine] = None, http_post=httpx.post):
        self._local_engine = local_engine or DockerScannerEngine()
        # Injectable for tests; a one-off call per package (not a
        # persistent client) for the same reason as EnrichmentService — this
        # engine is rebuilt on essentially every request.
        self._http_post = http_post

    def generate_sbom_for_image(self, image_string: str) -> Dict[str, Any]:
        return self._local_engine.generate_sbom_for_image(image_string)

    def generate_sbom_for_directory(self, work_dir: str, sub_path: str) -> Dict[str, Any]:
        return self._local_engine.generate_sbom_for_directory(work_dir, sub_path)

    def scan_secrets(self, work_dir: str, sub_path: str = "") -> list:
        return self._local_engine.scan_secrets(work_dir, sub_path)

    def scan_iac(self, work_dir: str, sub_path: str = "") -> list:
        return self._local_engine.scan_iac(work_dir, sub_path)

    def scan_sbom(self, work_dir: str, sbom: Dict[str, Any]) -> Dict[str, Any]:
        """Query OSV.dev once per SBOM component and return a Grype-shaped
        result (`{"matches": [...]}`), so the rest of the pipeline
        (`ScanProcessor._build_findings`, `_summarize_findings`, and the
        UI's CVE dialog) works unchanged regardless of which backend ran.
        """
        matches: List[Dict[str, Any]] = []
        for artifact in sbom.get("artifacts", []):
            purl = artifact.get("purl")
            if not purl:
                continue
            for vuln in self._query_osv(purl):
                matches.append(self._to_grype_like_match(vuln, artifact))

        # NOTE: intentionally not "source" — Grype's own JSON output already
        # has a top-level "source" object describing the scan target (e.g.
        # `{"type": "directory", "target": "..."}`), so reusing that key
        # here would collide with it and break the shared parsing code in
        # ScanProcessor._build_findings for the Docker backend.
        return {"matches": matches, "engine_source": "osv"}

    def _query_osv(self, purl: str) -> List[Dict[str, Any]]:
        try:
            response = self._http_post(
                OSV_QUERY_URL,
                json={"package": {"purl": purl}},
                timeout=OSV_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            return response.json().get("vulns", [])
        except Exception:
            # One bad/rate-limited lookup must not fail the whole scan —
            # skip it, same resilience contract as EnrichmentService.
            logger.exception("OSV.dev lookup failed for '%s' — skipping", purl)
            return []

    def _to_grype_like_match(self, vuln: Dict[str, Any], artifact: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = next(
            (alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")),
            vuln.get("id"),
        )
        references = vuln.get("references", [])
        link = references[0].get("url", "") if references else ""

        fixed_versions = self._fixed_versions(vuln)
        return {
            "vulnerability": {
                "id": cve_id,
                "severity": self._resolve_severity(vuln),
                "description": vuln.get("summary") or (vuln.get("details") or "")[:300],
                # Same keys Grype uses, so `extract_remediation` reads both
                # backends with one code path (ADR-001's whole point: the rest
                # of the pipeline must not know which engine ran).
                "fix": {
                    "state": "fixed" if fixed_versions else "unknown",
                    "versions": fixed_versions,
                },
                "cvss": self._cvss_entries(vuln),
                "links": [link] if link else [],
            },
            "artifact": {
                "name": artifact.get("name"),
                "version": artifact.get("version"),
                "purl": artifact.get("purl"),
                "locations": artifact.get("locations", []) or [],
            },
        }

    def _fixed_versions(self, vuln: Dict[str, Any]) -> List[str]:
        """Versions that fix the vulnerability, from OSV's range events.

        OSV expresses fixes as a timeline per affected range (`introduced`, then
        possibly `fixed`); an entry with no `fixed` event means no fix is
        published yet, which is exactly the distinction an operator needs.
        """
        versions = []
        for affected in vuln.get("affected") or []:
            for affected_range in affected.get("ranges") or []:
                for event in affected_range.get("events") or []:
                    fixed = event.get("fixed")
                    if fixed and fixed not in versions:
                        versions.append(str(fixed))
        return versions

    def _cvss_entries(self, vuln: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Translate OSV's `severity` list into Grype's `cvss` shape.

        Only the vector is carried over, never a numeric score: OSV publishes
        the vector string, and deriving a base score from it means implementing
        (or depending on) a CVSS calculator — a real dependency for a value the
        UI can already show as a vector. `Issue.cvss_score` therefore stays null
        on this backend, and the EPSS/KEV enrichment remains the numeric signal
        for prioritization.
        """
        entries = []
        for severity in vuln.get("severity") or []:
            vector = severity.get("score")
            if not isinstance(vector, str) or not vector.startswith("CVSS:"):
                continue
            # "CVSS:3.1/AV:N/..." → version 3.1
            version = vector.split("/", 1)[0].removeprefix("CVSS:")
            entries.append({"version": version, "vector": vector, "metrics": {}})
        return entries

    def _resolve_severity(self, vuln: Dict[str, Any]) -> str:
        db_specific = vuln.get("database_specific") or {}
        raw = (db_specific.get("severity") or "").lower()
        return _OSV_SEVERITY_MAP.get(raw, "unknown")

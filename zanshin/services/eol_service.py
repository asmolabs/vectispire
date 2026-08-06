"""End-of-life detection for the platforms and runtimes a target ships.

A whole class of risk has no CVE attached to it: a runtime past its end of life will
not receive a security fix for the *next* vulnerability, whatever that turns out to
be. Nothing in the scan pipeline saw that — a container built on an EOL distribution
reported the same clean bill of health as one on a supported release, right up to the
day a critical advisory landed and no patch followed.

Two matching paths, because the answer lives in two places in a Syft SBOM:

1. **The distribution**, from the SBOM's own `distro` block (`id`, `versionID`). This
   is the highest-value check for a container image and the one no package-level
   lookup would find: it is the base image's operating system, not a package in it.
2. **Packages**, matched by purl against endoflife.date's identifier index — one
   request returns roughly 940 purl-to-product mappings, so no hand-maintained
   mapping table is needed and none can rot.

Coverage is deliberately partial, and saying so matters: endoflife.date tracks
products — languages, runtimes, frameworks, databases, distributions — not every
library. An image with 131 packages will match a handful. That is the right scope,
because "end of life" is a property of a platform; an individual library's risk is
what the vulnerability scanners already answer.

Same contract as `EnrichmentService`: only product names and versions leave the
machine, never source or SBOM content, and any network failure is logged and
swallowed — a scan with valid results must never fail because an optional lookup
did not answer.
"""
import logging
import time
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

import httpx

from zanshin.models.finding import Finding
from zanshin.services.settings_service import SettingsService

logger = logging.getLogger(__name__)

API_ROOT = "https://endoflife.date/api/v1"
PURL_IDENTIFIERS_URL = f"{API_ROOT}/identifiers/purl/"

SETTING_KEY_EOL_ENABLED = "eol_detection_enabled"
SETTING_KEY_EOL_WARN_DAYS = "eol_warn_days"

# A cycle whose end of life falls inside this window is reported as a warning. Past
# it, nothing is reported: everything has an end of life eventually, and flagging a
# release supported for three more years would be noise that teaches people to
# filter the type out entirely.
DEFAULT_WARN_DAYS = 180

HTTP_TIMEOUT_SECONDS = 10.0
CACHE_TTL_SECONDS = 24 * 60 * 60

FINDING_TYPE = "eol"
SOURCE = "endoflife.date"


class EolService:
    """Produces `eol` findings from a scan's SBOM.

    Caches at the *class* level for the same reason as `EnrichmentService`: the IoC
    container rebuilds this service per request, so an instance cache would never be
    reused. The identifier index is one document; product documents are cached
    individually because a deployment scans the same few platforms repeatedly.
    """

    _purl_index: Optional[Dict[str, str]] = None
    _purl_index_fetched_at: float = 0.0
    _products: Dict[str, Optional[Dict[str, Any]]] = {}
    _products_fetched_at: Dict[str, float] = {}

    def __init__(self, settings_service: SettingsService, http_get=httpx.get):
        self.settings_service = settings_service
        self._http_get = http_get

    # --- Configuration ---

    def is_enabled(self) -> bool:
        return self.settings_service.get_setting(SETTING_KEY_EOL_ENABLED, "true") == "true"

    def warn_days(self) -> int:
        raw = self.settings_service.get_setting(SETTING_KEY_EOL_WARN_DAYS, "")
        try:
            days = int(raw)
        except (TypeError, ValueError):
            return DEFAULT_WARN_DAYS
        return days if days >= 0 else DEFAULT_WARN_DAYS

    # --- Entry point ---

    def build_findings(self, scan_id: int, sbom: Optional[Dict[str, Any]]) -> List[Finding]:
        """One finding per product cycle that is past — or close to — its end of life.

        Returns an empty list on any failure, including no network: this runs inside
        a scan that already produced results.
        """
        if not self.is_enabled() or not sbom:
            return []

        try:
            findings: List[Finding] = []
            seen: set = set()
            today = date.today()

            for product_name, version, package_label, purl in self._candidates(sbom):
                product = self._product(product_name)
                if not product:
                    continue
                release = self._match_release(product, version)
                if not release:
                    continue

                # Deduplicated on the *cycle*, not on the version: an image can list
                # the same runtime as both its distribution and a package, at "3.9"
                # and "3.9.1", and the finding is about the cycle either way. Keying
                # on the version would report the same end of life twice.
                key = (product_name, release["name"])
                if key in seen:
                    continue
                seen.add(key)

                verdict = self._assess(release, today)
                if not verdict:
                    continue
                severity, eol_date = verdict

                findings.append(Finding(
                    scan_id=scan_id,
                    type=FINDING_TYPE,
                    severity=severity,
                    # Stable across patch releases of the same cycle, because that is
                    # what the end-of-life date applies to: "python 3.9" reaches end
                    # of life, not "python 3.9.18". The fingerprint is built from
                    # this, so the issue keeps its history and its triage as the
                    # patch version moves.
                    identifier=f"EOL-{product_name}-{release['name']}",
                    package_name=package_label,
                    package_version=version,
                    purl=purl,
                    source=SOURCE,
                    link=f"https://endoflife.date/{product_name}",
                    fix_versions=self._recommended_version(product),
                    fix_state="fixed" if self._recommended_version(product) else "unknown",
                ))

            if findings:
                logger.info("End-of-life detection: %d product cycle(s) flagged", len(findings))
            return findings
        except Exception:
            logger.exception("End-of-life detection failed — skipping (non-fatal)")
            return []

    def describe(self, finding: Finding) -> str:
        """Free text for the issue, since `Finding` has no description column.

        Passed to `IssueService.sync_from_scan` through the same `descriptions` map
        that carries CVE descriptions.
        """
        return (
            f"{finding.package_name} {finding.package_version} appartient à un cycle "
            f"dont le support de sécurité est terminé ou proche de l'être. Aucun "
            f"correctif ne sera publié pour la prochaine vulnérabilité de ce composant, "
            f"quelle qu'elle soit."
        )

    # --- Matching ---

    def _candidates(self, sbom: Dict[str, Any]):
        """`(product, version, label, purl)` for everything worth looking up."""
        distro = sbom.get("distro") or {}
        distro_id = (distro.get("id") or "").strip().lower()
        distro_version = (distro.get("versionID") or "").strip()
        if distro_id and distro_version:
            # The distribution is matched by product name rather than by purl: a Syft
            # SBOM carries no purl for the operating system itself, and this is the
            # single most useful end-of-life answer for an image.
            product = self._resolve_product_name(distro_id)
            if product:
                yield product, distro_version, distro.get("name") or distro_id, None

        index = self._identifier_index()
        if not index:
            return
        for artifact in sbom.get("artifacts") or []:
            purl = artifact.get("purl")
            version = (artifact.get("version") or "").strip()
            if not purl or not version:
                continue
            product = index.get(_normalize_purl(purl))
            if product:
                yield product, version, artifact.get("name") or product, purl

    @staticmethod
    def _match_release(product: Dict[str, Any], version: str) -> Optional[Dict[str, Any]]:
        """The release cycle a version belongs to.

        Compared component by component, not with `startswith`: "3.14" starts with
        "3.1" as a string, so a prefix match would place Python 3.14 in the 3.1 cycle
        and report an end of life that passed years ago. The longest matching cycle
        wins, so a product listing both "8" and "8.1" resolves correctly.
        """
        wanted = _version_parts(version)
        best = None
        best_length = -1
        for release in product.get("releases") or []:
            parts = _version_parts(str(release.get("name") or ""))
            if not parts or len(parts) > len(wanted):
                continue
            if wanted[: len(parts)] == parts and len(parts) > best_length:
                best, best_length = release, len(parts)
        return best

    def _assess(self, release: Dict[str, Any], today: date) -> Optional[Tuple[str, Optional[date]]]:
        """`(severity, eol date)`, or `None` when the cycle is comfortably supported.

        A cycle already past its date is `high`: not because something is broken
        today, but because nothing will be fixed tomorrow, and that is not a "medium"
        for a component you ship. An upcoming date is `medium` — a deadline, not an
        incident.
        """
        eol_date = _parse_date(release.get("eolFrom"))

        if release.get("isEol") is True or (eol_date and eol_date <= today):
            return "high", eol_date
        if eol_date:
            days_left = (eol_date - today).days
            if 0 <= days_left <= self.warn_days():
                return "medium", eol_date
        # `isMaintained: false` without a date happens for discontinued products.
        if release.get("isMaintained") is False and not eol_date:
            return "high", None
        return None

    @staticmethod
    def _recommended_version(product: Dict[str, Any]) -> Optional[str]:
        """The newest maintained release, which is what "fix this" means here.

        Put on `fix_versions` so an end-of-life finding reads like every other
        actionable one, in the UI, the exports and the SARIF message.
        """
        for release in product.get("releases") or []:
            if release.get("isMaintained") and not release.get("isEol"):
                latest = (release.get("latest") or {}).get("name")
                return latest or str(release.get("name"))
        return None

    # --- Upstream catalogue ---

    def _identifier_index(self) -> Dict[str, str]:
        cls = type(self)
        if cls._purl_index is not None and time.time() - cls._purl_index_fetched_at < CACHE_TTL_SECONDS:
            return cls._purl_index

        payload = self._get_json(PURL_IDENTIFIERS_URL)
        index: Dict[str, str] = {}
        for entry in (payload or {}).get("result") or []:
            identifier = entry.get("identifier")
            product = ((entry.get("product") or {}).get("name") or "").strip()
            if identifier and product:
                index[_normalize_purl(identifier)] = product

        # Cached even when empty, so a failing upstream is retried on the next TTL
        # rather than on every single scan.
        cls._purl_index = index
        cls._purl_index_fetched_at = time.time()
        logger.info("End-of-life identifier index: %d purl mapping(s)", len(index))
        return index

    def _resolve_product_name(self, candidate: str) -> Optional[str]:
        """A distro id is usually the product name already (`rhel`, `alpine`,
        `debian`); asking for it directly is cheaper than downloading the product
        list to check first, and a 404 is the answer."""
        return candidate if self._product(candidate) else None

    def _product(self, name: str) -> Optional[Dict[str, Any]]:
        cls = type(self)
        cached_at = cls._products_fetched_at.get(name, 0.0)
        if name in cls._products and time.time() - cached_at < CACHE_TTL_SECONDS:
            return cls._products[name]

        payload = self._get_json(f"{API_ROOT}/products/{name}/")
        product = (payload or {}).get("result") if payload else None
        cls._products[name] = product
        cls._products_fetched_at[name] = time.time()
        return product

    def _get_json(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            response = self._http_get(url, timeout=HTTP_TIMEOUT_SECONDS)
            if response.status_code == 404:
                # An unknown product is information, not a failure.
                return None
            response.raise_for_status()
            return response.json()
        except Exception:
            logger.warning("End-of-life lookup failed for %s (non-fatal)", url, exc_info=True)
            return None

    @classmethod
    def clear_cache(cls) -> None:
        cls._purl_index = None
        cls._purl_index_fetched_at = 0.0
        cls._products = {}
        cls._products_fetched_at = {}


def _normalize_purl(purl: str) -> str:
    """`pkg:type/namespace/name`, without version or qualifiers.

    An SBOM purl carries both (`pkg:rpm/redhat/openssl@3.5.1?arch=x86_64`) while the
    catalogue's identifiers carry neither, so both sides are reduced to the part that
    identifies the *product* rather than the build.
    """
    value = (purl or "").strip()
    for separator in ("?", "#"):
        value = value.split(separator, 1)[0]
    if "@" in value:
        value = value.rsplit("@", 1)[0]
    return value.lower().rstrip("/")


def _version_parts(version: str) -> List[str]:
    """Numeric-ish components of a version, stopping at the first that isn't.

    `"9.7 (Plow)"` becomes `["9", "7"]` and `"3.12.1-rc1"` becomes `["3", "12", "1"]`:
    a distribution's pretty version and a package's build suffix must not prevent the
    cycle from being recognised.
    """
    cleaned = (version or "").strip().split(" ")[0]
    parts: List[str] = []
    for chunk in cleaned.split("."):
        digits = ""
        for character in chunk:
            if character.isdigit():
                digits += character
            else:
                break
        if not digits:
            break
        parts.append(digits)
    return parts


def _parse_date(value: Any) -> Optional[date]:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    except ValueError:
        return None

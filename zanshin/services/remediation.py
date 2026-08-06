"""Extraction of the "what do I do about it" half of a vulnerability match.

Grype and the OSV translation both report, per match, the version that fixes the
problem, a CVSS score/vector, a reference URL and a description. All of it was
being dropped: the pipeline kept only id/severity/package, so the UI could tell
an operator that something was wrong but never how to fix it — the single
cheapest gap to close in the whole product.

Kept out of `ScanProcessor` because it is pure parsing of scanner output, with
one genuinely non-obvious rule (see `extract_remediation`) that deserves to be
tested on its own.
"""
from typing import Any, Dict, List, NamedTuple, Optional

# Prefer the newest CVSS generation available. Grype reports whatever the
# upstream record carries, which for one CVE can be v2 *and* v3.1 at once.
_CVSS_VERSION_PRIORITY = ("4", "3.1", "3.0", "3", "2")


class Remediation(NamedTuple):
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    fix_state: Optional[str] = None
    fix_versions: Optional[str] = None
    link: Optional[str] = None
    description: Optional[str] = None


def extract_remediation(match: Dict[str, Any]) -> Remediation:
    """Pull remediation data out of one Grype-shaped match.

    The non-obvious part is `relatedVulnerabilities`. For an OS package, Grype's
    primary record is the *distribution's* advisory (RHSA, DSA, ...), which
    carries the vendor severity and the fixed package version but usually no
    CVSS metrics and no description — those live on the linked NVD record, which
    Grype puts in `relatedVulnerabilities`. Reading only the primary record
    therefore yields a null CVSS for exactly the findings a container scan
    produces most of, which is why this falls back to the related records for
    everything except the fix (the fix must stay the distribution's, since it's
    the distro-packaged version an operator can actually install).
    """
    vuln = match.get("vulnerability") or {}
    related: List[Dict[str, Any]] = [r for r in (match.get("relatedVulnerabilities") or []) if r]

    score, vector = _best_cvss(vuln)
    if score is None and vector is None:
        for record in related:
            score, vector = _best_cvss(record)
            if score is not None or vector is not None:
                break

    fix = vuln.get("fix") or {}
    versions = [str(v) for v in (fix.get("versions") or []) if v]
    fix_state = fix.get("state") or ("fixed" if versions else None)

    description = _first_text(vuln.get("description"), *[r.get("description") for r in related])
    link = _first_text(
        vuln.get("dataSource"),
        *(vuln.get("urls") or []),
        *[r.get("dataSource") for r in related],
    )
    # Some backends (and the OSV translation) report a `links` list instead.
    if not link:
        link = _first_text(*(vuln.get("links") or []))

    return Remediation(
        cvss_score=score,
        cvss_vector=vector,
        fix_state=fix_state,
        fix_versions=", ".join(versions) or None,
        link=_truncate(link, 500),
        description=description,
    )


def _best_cvss(record: Dict[str, Any]):
    """Highest-generation CVSS entry of a record, as (score, vector)."""
    entries = [e for e in (record.get("cvss") or []) if isinstance(e, dict)]
    if not entries:
        return None, None

    def rank(entry: Dict[str, Any]) -> int:
        version = str(entry.get("version") or "")
        for index, candidate in enumerate(_CVSS_VERSION_PRIORITY):
            if version.startswith(candidate):
                return index
        return len(_CVSS_VERSION_PRIORITY)

    best = sorted(entries, key=rank)[0]
    metrics = best.get("metrics") or {}
    raw_score = metrics.get("baseScore", best.get("baseScore"))
    try:
        score = float(raw_score) if raw_score is not None else None
    except (TypeError, ValueError):
        score = None
    return score, _truncate(best.get("vector"), 255)


def _first_text(*candidates) -> Optional[str]:
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def _truncate(value: Optional[str], limit: int) -> Optional[str]:
    if value is None:
        return None
    return value if len(value) <= limit else value[:limit]

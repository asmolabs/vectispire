"""Translation of Semgrep results into Zanshin findings, and the toggle that enables them.

**Why a service and not another `_build_*` method on `ScanIngestor`.** This step is the
only one that produces *two* finding types from one tool run, and the rule that decides
which is a piece of judgement rather than a mapping — so it needs somewhere to be
explained. The severity table, the confidence downgrade and the security/quality split
all live here, next to each other, because changing one without the others is how a rule
quietly stops being able to fail a build.

**The split.** Semgrep rules carry `metadata.category`. `security` becomes a `sast`
finding — an ordinary security finding, gated like any other. Everything else
(`correctness`, `best-practice`, `performance`, `maintainability`) becomes a `quality`
finding, which is visible in the backlog and, by construction, can never fail a CI gate:
see `policy_gate.QUALITY_TYPES`. Turning on a code scanner should not break everyone's
pipeline on the morning it ships.

**What it deliberately does not do.** It does not contribute to `scan.summary` or
`scan.findings_count`. Those count vulnerabilities, they feed `SeverityCounts` and the
dashboard, and mixing three hundred style findings into them would make the headline
number of a scan mean nothing.
"""
import logging
from typing import Any, Dict, List, Optional

from zanshin.models.finding import Finding

logger = logging.getLogger(__name__)

SETTING_KEY_SAST_ENABLED = "sast_enabled"

FINDING_TYPE_SAST = "sast"
FINDING_TYPE_QUALITY = "quality"

# Semgrep's three levels, mapped explicitly rather than lowercased.
#
# `"ERROR".lower()` is `"error"`, which is not in `policy_gate.SEVERITY_ORDER`. A value
# outside that vocabulary does not raise anywhere — it sorts below `negligible` in the
# backlog, invents a key in the severity tally, can never satisfy a gate threshold, and
# falls back to `warning` in the SARIF export. All silently. Hence the table.
SEVERITY_BY_SEMGREP_LEVEL = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}
DEFAULT_SEVERITY = "unknown"

# Severity ladder used for the confidence downgrade below. Kept local and ordered
# worst-first, matching `policy_gate.SEVERITY_ORDER`.
_SEVERITY_LADDER = ("critical", "high", "medium", "low", "negligible")


class SastService:
    """Owns the `sast_enabled` setting and the Semgrep → `Finding` translation."""

    def __init__(self, settings_service=None):
        # Optional so the translation can be used without a database — the same
        # separation the runner/ingestor split exists for.
        self.settings_service = settings_service

    # --- The toggle -------------------------------------------------------------

    def is_enabled(self) -> bool:
        """Off by default.

        Unlike the other scanners, this one reads every source file of a repository and
        can produce hundreds of findings on its first run. Making an operator opt in
        means the day the backlog grows by a thousand entries is a day somebody chose.
        """
        if not self.settings_service:
            return False
        return self.settings_service.get_setting(SETTING_KEY_SAST_ENABLED, "false") == "true"

    def set_enabled(self, enabled: bool) -> None:
        if not self.settings_service:
            raise RuntimeError("SastService has no settings service to write to")
        self.settings_service.update_setting(
            SETTING_KEY_SAST_ENABLED, "true" if enabled else "false"
        )

    # --- The translation --------------------------------------------------------

    def build_findings(
        self, scan_id: int, results: Optional[List[Dict[str, Any]]]
    ) -> Optional[List[Finding]]:
        """Turn Semgrep `results` entries into `Finding` rows.

        `None` in, `None` out: it propagates "the analysis did not run", which is what
        stops the ingestor from resolving a target's whole SAST backlog after a Semgrep
        failure. An empty list in gives an empty list out — "analysed, clean".

        Paths arrive already relative to the repository: the engine rewrites the
        container-side path it alone knows about, so a finding's identity does not depend
        on where the scan ran.
        """
        if results is None:
            return None

        findings: List[Finding] = []
        for result in results:
            metadata = (result.get("extra") or {}).get("metadata") or {}
            findings.append(
                Finding(
                    scan_id=scan_id,
                    type=self.finding_type_of(metadata),
                    severity=self.severity_of(result),
                    identifier=result.get("check_id"),
                    file_path=(result.get("path") or "").lstrip("/") or None,
                    line=(result.get("start") or {}).get("line"),
                    description=((result.get("extra") or {}).get("message") or "").strip() or None,
                    source="semgrep",
                )
            )
        return findings

    @staticmethod
    def finding_type_of(metadata: Dict[str, Any]) -> str:
        """`sast` for a security rule, `quality` for anything else.

        A rule with no category at all is treated as quality: an unclassified rule that
        could fail somebody's build is the worse of the two mistakes.
        """
        category = (metadata.get("category") or "").strip().lower()
        return FINDING_TYPE_SAST if category == "security" else FINDING_TYPE_QUALITY

    @classmethod
    def severity_of(cls, result: Dict[str, Any]) -> str:
        """Semgrep's level, lowered one notch when the rule declares low confidence.

        Downgraded rather than dropped, for two reasons. A dropped finding is gone —
        and worse, it comes back as brand new the day the rule's metadata changes,
        losing whatever triage it had. And the default gate threshold is `high`, so a
        low-confidence `ERROR` landing on `medium` is precisely "visible in the backlog,
        unable to break a build" — the same treatment `policy_gate` already argues for
        AI-review findings.
        """
        extra = result.get("extra") or {}
        severity = SEVERITY_BY_SEMGREP_LEVEL.get(
            (extra.get("severity") or "").strip().upper(), DEFAULT_SEVERITY
        )
        confidence = ((extra.get("metadata") or {}).get("confidence") or "").strip().upper()
        if confidence == "LOW":
            severity = _one_notch_down(severity)
        return severity


def _one_notch_down(severity: str) -> str:
    try:
        index = _SEVERITY_LADDER.index(severity)
    except ValueError:
        return severity
    return _SEVERITY_LADDER[min(index + 1, len(_SEVERITY_LADDER) - 1)]

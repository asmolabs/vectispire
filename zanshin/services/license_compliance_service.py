from typing import Any, Dict, List, Set

from zanshin.models.finding import Finding
from zanshin.services.settings_service import SettingsService

# Stored in the generic `setting` key/value table (see SettingsService).
# Comma-separated SPDX identifiers, e.g. "GPL-3.0-only,AGPL-3.0-only".
SETTING_KEY_LICENSE_BLOCKLIST = "license_blocklist"

class LicenseComplianceService:
    """Flags SBOM components whose license is on a configurable blocklist.

    Unlike vulnerability or secret scanning, this needs no new scanning
    tool: Syft already records each component's license(s) in the SBOM it
    generates for every scan — container image or directory — so this is
    pure rule evaluation over data that's already collected (see ADR-001,
    section 5). Which licenses are disallowed is an organization policy
    decision, not a technical one, so nothing is flagged until a blocklist
    is explicitly configured (empty by default).
    """

    def __init__(self, settings_service: SettingsService):
        self.settings_service = settings_service

    def get_blocklist(self) -> Set[str]:
        raw = self.settings_service.get_setting(SETTING_KEY_LICENSE_BLOCKLIST, "")
        return {item.strip().upper() for item in raw.split(",") if item.strip()}

    def build_findings(self, scan_id: int, sbom: Dict[str, Any]) -> List[Finding]:
        blocklist = self.get_blocklist()
        if not blocklist:
            return []

        findings = []
        for artifact in sbom.get("artifacts", []):
            for license_value in self._extract_licenses(artifact):
                if license_value.upper() in blocklist:
                    findings.append(Finding(
                        scan_id=scan_id,
                        type="license",
                        severity="medium",
                        identifier=license_value,
                        package_name=artifact.get("name"),
                        package_version=artifact.get("version"),
                        purl=artifact.get("purl"),
                        source="syft",
                            ))
        return findings

    def _extract_licenses(self, artifact: Dict[str, Any]) -> List[str]:
        """Syft has represented per-component licenses both as plain strings
        and, in newer schema versions, as objects (e.g. `{"value": "MIT",
        "spdxExpression": "MIT", ...}`) — handle both defensively so this
        doesn't silently break on a Syft version bump."""
        values = []
        for entry in artifact.get("licenses", []) or []:
            if isinstance(entry, str):
                values.append(entry)
            elif isinstance(entry, dict):
                value = entry.get("value") or entry.get("spdxExpression")
                if value:
                    values.append(value)
        return values

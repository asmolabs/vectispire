"""Outbound notifications about what a scan changed.

`NotificationGateway` used to log a line and nothing else, which was defensible
while the only thing worth saying was "a scan finished" — a message nobody needs.
What made notifications worth building is the issue delta: "3 new problems, one of
them actively exploited, a fix is available" is actionable, and it is exactly what
a periodic scan at 3am produces while nobody is looking at the dashboard.

Design decisions:

- **A generic webhook, not a Slack integration.** One HTTP POST with a documented
  JSON body reaches Slack and Teams (via a workflow), Discord, Mattermost, an
  internal bus, or a three-line script. A vendor-specific payload would buy
  prettier formatting in one place at the cost of everywhere else, and a `text`
  field is included so the common chat sinks render something readable anyway.
- **Only on change, and only above a threshold.** A notification per scan trains
  people to filter the channel. Nothing new above the configured severity means
  no message at all.
- **Never able to fail a scan.** Same contract as enrichment and the AI review:
  the scan's results are already committed, and an unreachable webhook is an
  operations problem, not a scan failure.
"""
import logging
from typing import Any, Dict, List, Optional

import httpx

from zanshin.models.issue import Issue
from zanshin.services.policy_gate import is_at_least
from zanshin.services.settings_service import SettingsService
from zanshin.services.url_guard import UnsafeUrlError, validate_outbound_url

logger = logging.getLogger(__name__)

SETTING_KEY_WEBHOOK_URL = "notification_webhook_url"
SETTING_KEY_MIN_SEVERITY = "notification_min_severity"
SETTING_KEY_NOTIFY_ON_KEV = "notification_always_on_kev"
# Escape hatch for an internal bus. Off by default: a webhook URL that resolves to
# a private address is far more often an SSRF attempt than an intranet endpoint.
SETTING_KEY_ALLOW_PRIVATE = "notification_allow_private_url"

DEFAULT_MIN_SEVERITY = "high"
HTTP_TIMEOUT_SECONDS = 10.0

# How many issues to name in the payload. The rest are counted: a webhook body
# with four hundred entries is a denial of service against the reader, and the
# API is there for the full list.
MAX_DETAILED_ISSUES = 10


class NotificationService:
    """Posts a scan's delta to a configured webhook, if there is anything to say."""

    def __init__(self, settings_service: SettingsService, http_post=httpx.post):
        self.settings_service = settings_service
        # Injectable for tests; a one-off call rather than a persistent client for
        # the same reason as EnrichmentService — this service is rebuilt per
        # request by IoCContainer.
        self._http_post = http_post

    def webhook_url(self) -> str:
        return (self.settings_service.get_setting(SETTING_KEY_WEBHOOK_URL, "") or "").strip()

    def is_enabled(self) -> bool:
        return bool(self.webhook_url())

    def min_severity(self) -> str:
        return (
            self.settings_service.get_setting(SETTING_KEY_MIN_SEVERITY, DEFAULT_MIN_SEVERITY)
            or DEFAULT_MIN_SEVERITY
        ).lower()

    def allow_private_url(self) -> bool:
        return self.settings_service.get_setting(SETTING_KEY_ALLOW_PRIVATE, "false") == "true"

    def always_on_kev(self) -> bool:
        return self.settings_service.get_setting(SETTING_KEY_NOTIFY_ON_KEV, "true") == "true"

    def select_notable(self, issues: List[Issue]) -> List[Issue]:
        """Which of a scan's new/reopened issues are worth a message.

        A known-exploited vulnerability passes regardless of its severity bucket
        when `always_on_kev` is set — that is the whole point of the KEV signal,
        and severity alone would drop a "medium" being exploited today.
        """
        threshold = self.min_severity()
        notable = []
        for issue in issues:
            if self.always_on_kev() and issue.is_kev:
                notable.append(issue)
            elif is_at_least(issue.severity, threshold):
                notable.append(issue)
        return notable

    def notify_scan_delta(
        self,
        *,
        target_name: str,
        scan_id: int,
        new_issues: List[Issue],
        reopened_issues: Optional[List[Issue]] = None,
        resolved_count: int = 0,
    ) -> bool:
        """Send the notification. Returns whether anything was sent.

        Never raises: a webhook failure is logged and swallowed.
        """
        if not self.is_enabled():
            return False

        reopened_issues = reopened_issues or []
        notable_new = self.select_notable(new_issues)
        notable_reopened = self.select_notable(reopened_issues)
        if not notable_new and not notable_reopened:
            logger.debug("Scan %s: nothing notable to notify", scan_id)
            return False

        # Re-validated here, not only at save time: the setting may predate the
        # guard, or have been written straight into the database.
        try:
            url = validate_outbound_url(
                self.webhook_url(),
                allow_private=self.allow_private_url(),
                label="URL de webhook",
            )
        except UnsafeUrlError as e:
            logger.error("Notification not sent: %s", e)
            return False

        payload = self.build_payload(
            target_name=target_name,
            scan_id=scan_id,
            new_issues=notable_new,
            reopened_issues=notable_reopened,
            resolved_count=resolved_count,
        )
        try:
            response = self._http_post(url, json=payload, timeout=HTTP_TIMEOUT_SECONDS)
            response.raise_for_status()
            logger.info(
                "Notified webhook about scan %s (%d new, %d reopened)",
                scan_id, len(notable_new), len(notable_reopened),
            )
            return True
        except Exception:
            logger.exception("Notification webhook failed for scan %s (non-fatal)", scan_id)
            return False

    def build_payload(
        self,
        *,
        target_name: str,
        scan_id: int,
        new_issues: List[Issue],
        reopened_issues: List[Issue],
        resolved_count: int,
    ) -> Dict[str, Any]:
        """The webhook body. `text` first so chat sinks that only read that field
        still render something useful."""
        headline_parts = []
        if new_issues:
            headline_parts.append(f"{len(new_issues)} nouveau(x) problème(s)")
        if reopened_issues:
            headline_parts.append(f"{len(reopened_issues)} réapparu(s)")
        kev_count = sum(1 for i in new_issues + reopened_issues if i.is_kev)
        if kev_count:
            headline_parts.append(f"{kev_count} activement exploité(s)")

        text = f"Zanshin — {target_name} : " + ", ".join(headline_parts)
        if resolved_count:
            text += f" ({resolved_count} résolu(s))"

        return {
            "text": text,
            "target": target_name,
            "scan_id": scan_id,
            "new_count": len(new_issues),
            "reopened_count": len(reopened_issues),
            "resolved_count": resolved_count,
            "kev_count": kev_count,
            "min_severity": self.min_severity(),
            "issues": [
                self._issue_payload(issue)
                for issue in (new_issues + reopened_issues)[:MAX_DETAILED_ISSUES]
            ],
            "truncated": max(0, len(new_issues) + len(reopened_issues) - MAX_DETAILED_ISSUES),
        }

    @staticmethod
    def _issue_payload(issue: Issue) -> Dict[str, Any]:
        return {
            "id": issue.id,
            "identifier": issue.identifier,
            "type": issue.type,
            "severity": issue.severity,
            "is_kev": bool(issue.is_kev),
            "epss_score": issue.epss_score,
            "package": issue.package_name,
            "file_path": issue.file_path,
            # The single most useful field for whoever reads the alert.
            "fix_versions": issue.fix_versions,
            "link": issue.link,
        }

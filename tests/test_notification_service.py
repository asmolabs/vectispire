"""Tests for outbound notifications.

The behaviours that decide whether a channel stays read: nothing is sent when a
scan changed nothing, a known-exploited vulnerability gets through regardless of
its severity bucket, and a webhook failure can never affect the scan.
"""
import pytest

from zanshin.models.issue import Issue
from zanshin.models.setting import Setting
from zanshin.services.notification_service import (
    MAX_DETAILED_ISSUES,
    SETTING_KEY_MIN_SEVERITY,
    SETTING_KEY_NOTIFY_ON_KEV,
    SETTING_KEY_WEBHOOK_URL,
    NotificationService,
)

WEBHOOK = "https://hooks.example.com/T000/B000/xxxx"

_next_id = iter(range(1, 10_000))


def _issue(**kwargs):
    defaults = dict(
        id=next(_next_id),
        type="vulnerability",
        identifier="CVE-2024-0001",
        severity="high",
        is_kev=False,
        package_name="libfoo",
    )
    defaults.update(kwargs)
    return Issue(**defaults)


class FakePoster:
    def __init__(self, error=None):
        self.calls = []
        self.error = error

    def __call__(self, url, json=None, timeout=None):
        self.calls.append((url, json))
        if self.error:
            raise self.error

        class Response:
            def raise_for_status(self):
                pass

        return Response()


@pytest.fixture()
def service(settings_service, setting_repository):
    def _build(url=WEBHOOK, min_severity=None, on_kev=None, poster=None):
        if url is not None:
            setting_repository.save(Setting(key=SETTING_KEY_WEBHOOK_URL, value=url))
        if min_severity:
            setting_repository.save(Setting(key=SETTING_KEY_MIN_SEVERITY, value=min_severity))
        if on_kev is not None:
            setting_repository.save(Setting(key=SETTING_KEY_NOTIFY_ON_KEV, value=on_kev))
        poster = poster or FakePoster()
        return NotificationService(settings_service, http_post=poster), poster

    return _build


# --- When to send ---

def test_disabled_until_a_webhook_url_is_configured(service):
    svc, poster = service(url="")

    assert svc.is_enabled() is False
    assert svc.notify_scan_delta(target_name="app", scan_id=1, new_issues=[_issue()]) is False
    assert poster.calls == []


def test_nothing_is_sent_when_a_scan_changed_nothing(service):
    """A notification per scan trains people to mute the channel."""
    svc, poster = service()

    assert svc.notify_scan_delta(target_name="app", scan_id=1, new_issues=[]) is False
    assert poster.calls == []


def test_nothing_is_sent_when_everything_new_is_below_the_threshold(service):
    svc, poster = service(min_severity="high")

    sent = svc.notify_scan_delta(
        target_name="app", scan_id=1, new_issues=[_issue(severity="low"), _issue(severity="medium")]
    )

    assert sent is False
    assert poster.calls == []


def test_sends_when_something_new_meets_the_threshold(service):
    svc, poster = service(min_severity="high")

    sent = svc.notify_scan_delta(
        target_name="app", scan_id=7, new_issues=[_issue(severity="critical")]
    )

    assert sent is True
    url, payload = poster.calls[0]
    assert url == WEBHOOK
    assert payload["scan_id"] == 7


def test_a_known_exploited_vulnerability_gets_through_any_threshold(service):
    """That is the whole point of the KEV signal: severity alone would drop a
    "medium" that is being exploited today."""
    svc, poster = service(min_severity="critical")

    sent = svc.notify_scan_delta(
        target_name="app", scan_id=1, new_issues=[_issue(severity="medium", is_kev=True)]
    )

    assert sent is True
    assert poster.calls[0][1]["kev_count"] == 1


def test_kev_override_can_be_turned_off(service):
    svc, poster = service(min_severity="critical", on_kev="false")

    sent = svc.notify_scan_delta(
        target_name="app", scan_id=1, new_issues=[_issue(severity="medium", is_kev=True)]
    )

    assert sent is False


def test_reopened_issues_are_notified_too(service):
    """A regression is at least as interesting as a discovery."""
    svc, poster = service()

    sent = svc.notify_scan_delta(
        target_name="app", scan_id=1, new_issues=[], reopened_issues=[_issue(severity="critical")]
    )

    assert sent is True
    payload = poster.calls[0][1]
    assert payload["reopened_count"] == 1
    assert payload["new_count"] == 0


# --- Payload ---

def test_payload_leads_with_a_human_readable_line(service):
    """Slack, Teams and Discord all render `text`; a structured-only body would
    show up as an empty message in the most common sinks."""
    svc, poster = service()

    svc.notify_scan_delta(
        target_name="registry.internal/nginx:1.25",
        scan_id=13,
        new_issues=[_issue(severity="critical"), _issue(severity="high", is_kev=True)],
        resolved_count=8,
    )

    text = poster.calls[0][1]["text"]
    assert "registry.internal/nginx:1.25" in text
    assert "2 nouveau(x)" in text
    assert "1 activement exploité(s)" in text
    assert "8 résolu(s)" in text


def test_payload_carries_the_fix_for_each_issue(service):
    """The single most useful field for whoever reads the alert."""
    svc, poster = service()

    svc.notify_scan_delta(
        target_name="app",
        scan_id=1,
        new_issues=[_issue(severity="critical", fix_versions="1.2.3", link="https://x/CVE")],
    )

    issue_payload = poster.calls[0][1]["issues"][0]
    assert issue_payload["fix_versions"] == "1.2.3"
    assert issue_payload["link"] == "https://x/CVE"
    assert issue_payload["identifier"] == "CVE-2024-0001"


def test_the_issue_list_is_capped_and_says_so(service):
    """A webhook body with four hundred entries is a denial of service against
    the reader; the API is there for the full list."""
    svc, poster = service()
    issues = [_issue(severity="critical") for _ in range(MAX_DETAILED_ISSUES + 5)]

    svc.notify_scan_delta(target_name="app", scan_id=1, new_issues=issues)

    payload = poster.calls[0][1]
    assert len(payload["issues"]) == MAX_DETAILED_ISSUES
    assert payload["truncated"] == 5
    assert payload["new_count"] == MAX_DETAILED_ISSUES + 5  # the count is not capped


# --- Resilience ---

def test_a_webhook_failure_is_swallowed(service):
    """Same contract as enrichment and the AI review: the scan's results are
    already committed, and an unreachable webhook is an ops problem."""
    svc, poster = service(poster=FakePoster(error=RuntimeError("connection refused")))

    sent = svc.notify_scan_delta(
        target_name="app", scan_id=1, new_issues=[_issue(severity="critical")]
    )

    assert sent is False  # reported, not raised
    assert len(poster.calls) == 1


def test_select_notable_is_usable_on_its_own(service):
    """Exposed so the same threshold logic can back a UI badge later without
    re-deriving it."""
    svc, _ = service(min_severity="high")

    notable = svc.select_notable(
        [_issue(severity="low"), _issue(severity="high"), _issue(severity="low", is_kev=True)]
    )

    assert len(notable) == 2

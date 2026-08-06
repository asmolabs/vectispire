"""Tests for the OpenVEX and CSV exports.

The VEX document is the one output someone else consumes — a customer, an auditor,
another tool — so the cases below are about the statements being *true*: no
statement without a subject, no `not_affected` without its required justification,
and no "still investigating" about something the scanner stopped seeing.
"""
from datetime import datetime

import pytest

from zanshin.models.issue import (
    STATE_OPEN,
    STATE_RESOLVED,
    TRIAGE_AFFECTED,
    TRIAGE_FIXED,
    TRIAGE_NOT_AFFECTED,
    TRIAGE_UNDER_REVIEW,
    Issue,
)
from zanshin.services.exports import (
    OPENVEX_CONTEXT,
    build_issues_csv,
    build_openvex_document,
)

TIMESTAMP = "2026-08-06T12:00:00"
PRODUCT = "git@example.com:org/app.git"

_next_id = iter(range(1, 10_000))


def _issue(**kwargs):
    defaults = dict(
        id=next(_next_id),
        type="vulnerability",
        identifier="CVE-2024-0001",
        severity="high",
        state=STATE_OPEN,
        triage_status=TRIAGE_UNDER_REVIEW,
        is_kev=False,
        times_seen=1,
        package_name="libfoo",
        package_version="1.0.0",
        purl="pkg:deb/libfoo@1.0.0",
        first_seen_at=datetime(2026, 1, 1, 8, 0),
        last_seen_at=datetime(2026, 8, 1, 8, 0),
    )
    defaults.update(kwargs)
    return Issue(**defaults)


def _document(issues):
    return build_openvex_document(
        issues,
        author="Zanshin",
        product_id=PRODUCT,
        document_id="https://zanshin.local/vex/repository/1",
        timestamp=TIMESTAMP,
    )


# --- Document shape ---

def test_document_carries_the_required_openvex_metadata():
    document = _document([_issue()])

    assert document["@context"] == OPENVEX_CONTEXT
    assert document["@id"].endswith("/repository/1")
    assert document["author"] == "Zanshin"
    assert document["timestamp"] == TIMESTAMP
    assert document["version"] == 1


def test_statement_names_the_vulnerability_and_the_product():
    statement = _document([_issue(identifier="CVE-2024-9999")])["statements"][0]

    assert statement["vulnerability"] == {"name": "CVE-2024-9999"}
    assert statement["products"][0]["@id"] == PRODUCT
    assert statement["products"][0]["identifiers"]["purl"] == "pkg:deb/libfoo@1.0.0"


# --- Status mapping ---

def test_under_review_maps_to_the_specifications_spelling():
    """Zanshin says `under_review`, OpenVEX says `under_investigation`. The
    document has to speak the specification's language, not ours."""
    statement = _document([_issue(triage_status=TRIAGE_UNDER_REVIEW)])["statements"][0]
    assert statement["status"] == "under_investigation"


@pytest.mark.parametrize(
    ("triage", "expected"),
    [(TRIAGE_AFFECTED, "affected"), (TRIAGE_FIXED, "fixed")],
)
def test_statuses_that_map_directly(triage, expected):
    statement = _document([_issue(triage_status=triage)])["statements"][0]
    assert statement["status"] == expected


def test_not_affected_carries_its_justification():
    """Required by the specification for this status; a `not_affected` statement
    without one is invalid, which is why `IssueService.triage` refuses to record
    it in the first place."""
    issue = _issue(
        triage_status=TRIAGE_NOT_AFFECTED,
        triage_justification="vulnerable_code_not_present",
        triage_comment="le module n'est pas compilé",
    )

    statement = _document([issue])["statements"][0]

    assert statement["status"] == "not_affected"
    assert statement["justification"] == "vulnerable_code_not_present"
    assert statement["impact_statement"] == "le module n'est pas compilé"


def test_affected_puts_free_text_in_the_action_statement():
    issue = _issue(triage_status=TRIAGE_AFFECTED, triage_comment="montée de version prévue")

    statement = _document([issue])["statements"][0]

    assert statement["action_statement"] == "montée de version prévue"
    assert "justification" not in statement


def test_a_resolved_untriaged_issue_is_reported_as_fixed():
    """It is factually gone: the scanner stopped seeing it. Publishing "under
    investigation" about something that no longer exists would mislead exactly
    the reader this document is for."""
    statement = _document(
        [_issue(state=STATE_RESOLVED, triage_status=TRIAGE_UNDER_REVIEW)]
    )["statements"][0]

    assert statement["status"] == "fixed"


def test_a_human_verdict_survives_resolution():
    """If someone judged it not affected, that judgment is the statement — the
    scanner's silence doesn't overrule it."""
    issue = _issue(
        state=STATE_RESOLVED,
        triage_status=TRIAGE_NOT_AFFECTED,
        triage_justification="component_not_present",
    )

    assert _document([issue])["statements"][0]["status"] == "not_affected"


# --- What must not appear ---

def test_non_vulnerability_issues_are_excluded():
    """VEX is defined over vulnerability identifiers; a hardcoded secret or a
    failed IaC check has no CVE to make a statement about."""
    issues = [
        _issue(type="secret", identifier="aws-key"),
        _issue(type="iac", identifier="CKV_AWS_1"),
        _issue(type="license", identifier="GPL-3.0-only"),
        _issue(type="vulnerability", identifier="CVE-2024-0001"),
    ]

    statements = _document(issues)["statements"]

    assert len(statements) == 1
    assert statements[0]["vulnerability"]["name"] == "CVE-2024-0001"


def test_issues_without_an_identifier_are_skipped():
    assert _document([_issue(identifier=None)])["statements"] == []


def test_timestamp_prefers_the_triage_date_then_the_last_sighting():
    triaged = _issue(triaged_at=datetime(2026, 7, 1, 9, 30), triage_status=TRIAGE_AFFECTED)
    untriaged = _issue()

    statements = _document([triaged, untriaged])["statements"]

    assert statements[0]["timestamp"] == "2026-07-01T09:30:00"
    assert statements[1]["timestamp"] == "2026-08-01T08:00:00"


# --- CSV ---

def test_csv_has_a_header_and_one_row_per_issue():
    csv_text = build_issues_csv([_issue(), _issue(type="secret", identifier="aws-key")])
    lines = csv_text.strip().splitlines()

    assert lines[0].startswith("id,type,identifier,severity")
    assert len(lines) == 3


def test_csv_renders_every_kind_of_empty_value_as_empty_not_none():
    """"None" in a spreadsheet cell is a bug report waiting to happen."""
    csv_text = build_issues_csv(
        [_issue(identifier=None, purl=None, cvss_score=None, epss_score=None, fix_versions=None)]
    )

    assert "None" not in csv_text


def test_csv_carries_the_triage_decision_and_the_history():
    issue = _issue(
        triage_status=TRIAGE_NOT_AFFECTED,
        triage_justification="inline_mitigations_already_exist",
        triaged_by="alice",
        triaged_at=datetime(2026, 7, 1, 9, 30),
        times_seen=4,
        is_kev=True,
    )

    row = build_issues_csv([issue]).strip().splitlines()[1]

    assert "not_affected" in row
    assert "inline_mitigations_already_exist" in row
    assert "alice" in row
    assert "2026-07-01T09:30:00" in row
    assert "true" in row  # is_kev


def test_csv_of_nothing_is_still_a_valid_csv():
    assert build_issues_csv([]).strip().startswith("id,type,")

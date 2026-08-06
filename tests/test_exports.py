"""Tests for the SARIF, OpenVEX and CSV exports.

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
    SARIF_VERSION,
    build_issues_csv,
    build_openvex_document,
    build_sarif_document,
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


# --- SARIF ---
#
# The output feeds a code-scanning platform, so the tests are about the things that
# make a technically valid document useless in one: a result with no location is
# dropped, a triaged issue that vanishes comes back as new, and a severity that
# collapses to "warning" is scrolled past.

def _sarif(issues, **kwargs):
    kwargs.setdefault("target_name", PRODUCT)
    return build_sarif_document(issues, **kwargs)


def test_the_document_declares_the_version_a_platform_checks():
    document = _sarif([_issue()])

    assert document["version"] == SARIF_VERSION
    assert document["runs"][0]["tool"]["driver"]["name"] == "Zanshin"


def test_a_rule_is_emitted_once_for_several_issues_sharing_an_identifier():
    """SARIF's model groups results under rules, and a platform's UI groups by
    them — one rule per issue would defeat both."""
    issues = [_issue(package_name="libfoo"), _issue(package_name="libbar")]

    run = _sarif(issues)["runs"][0]

    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2
    assert {r["ruleIndex"] for r in run["results"]} == {0}


def test_two_finding_types_sharing_an_identifier_stay_separate_rules():
    """A gitleaks rule and a checkov check can collide on a name; merged under one
    ruleId a platform would present them as the same class of problem."""
    issues = [
        _issue(type="secret", identifier="generic-api-key", file_path="a.py"),
        _issue(type="iac", identifier="generic-api-key", file_path="main.tf"),
    ]

    rules = _sarif(issues)["runs"][0]["tool"]["driver"]["rules"]

    assert len({rule["id"] for rule in rules}) == 2


@pytest.mark.parametrize(
    "severity,level",
    [("critical", "error"), ("high", "error"), ("medium", "warning"), ("low", "note")],
)
def test_severity_maps_onto_sarif_levels(severity, level):
    result = _sarif([_issue(severity=severity)])["runs"][0]["results"][0]

    assert result["level"] == level


def test_critical_and_high_stay_distinguishable_despite_both_being_errors():
    """SARIF has no "critical", so the distinction has to survive somewhere:
    GitHub ranks on `security-severity`, not on `level`."""
    critical = _sarif([_issue(severity="critical")])["runs"][0]
    high = _sarif([_issue(severity="high")])["runs"][0]

    critical_score = critical["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    high_score = high["tool"]["driver"]["rules"][0]["properties"]["security-severity"]
    assert float(critical_score) > float(high_score)


def test_every_result_has_a_location():
    """GitHub silently drops results without one, and dependency issues — the bulk
    of them — have no file. An "honest" empty location would mean they never
    appeared at all."""
    result = _sarif([_issue(file_path=None)])["runs"][0]["results"][0]

    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "."


def test_a_finding_with_a_line_is_annotated_on_that_line():
    result = _sarif([_issue(type="secret", file_path="app/config.py", line=42)])["runs"][0]["results"][0]

    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "app/config.py"
    assert physical["region"]["startLine"] == 42


def test_the_message_says_what_to_do():
    """What a developer reads in the pull request. The fixed version is the whole
    difference between "there is a CVE" and "change this line"."""
    result = _sarif([_issue(fix_versions="1.2.3", is_kev=True)])["runs"][0]["results"][0]

    message = result["message"]["text"]
    assert "libfoo 1.0.0" in message
    assert "1.2.3" in message
    assert "KEV" in message


def test_a_triaged_issue_is_suppressed_rather_than_dropped():
    """Dropping it would make the platform re-report it as new on the next upload,
    undoing the triage work — and the suppression carries the reason."""
    issue = _issue(
        triage_status=TRIAGE_NOT_AFFECTED,
        triage_justification="vulnerable_code_not_in_execute_path",
        triage_comment="Chemin non atteignable dans notre configuration",
        triaged_by="alice",
    )

    result = _sarif([issue])["runs"][0]["results"][0]

    assert result["suppressions"][0]["kind"] == "external"
    justification = result["suppressions"][0]["justification"]
    assert "vulnerable_code_not_in_execute_path" in justification
    assert "alice" in justification


def test_an_affected_issue_is_not_suppressed():
    """Deciding a problem is real must not hide it."""
    result = _sarif([_issue(triage_status=TRIAGE_AFFECTED)])["runs"][0]["results"][0]

    assert "suppressions" not in result


def test_a_review_date_is_stated_in_the_suppression():
    issue = _issue(
        triage_status=TRIAGE_FIXED,
        triage_expires_at=datetime(2026, 12, 1, 8, 0),
    )

    justification = _sarif([issue])["runs"][0]["results"][0]["suppressions"][0]["justification"]

    assert "2026-12-01" in justification


def test_resolved_issues_are_left_out():
    """SARIF here describes the current state of the branch being built, and a
    resolved issue is not in it."""
    run = _sarif([_issue(state=STATE_RESOLVED), _issue(state=STATE_OPEN)])["runs"][0]

    assert len(run["results"]) == 1


def test_the_fingerprint_lets_a_platform_match_across_uploads():
    """Without it a platform re-identifies findings by file and line, so a moved
    file or a shifted line reads as a new problem — and as a resolved one."""
    result = _sarif([_issue(fingerprint="deadbeef")])["runs"][0]["results"][0]

    assert result["partialFingerprints"]["zanshinIssueFingerprint"] == "deadbeef"


def test_directness_travels_with_the_result():
    direct = _sarif([_issue(is_direct_dependency=True)])["runs"][0]["results"][0]
    transitive = _sarif([_issue(is_direct_dependency=False)])["runs"][0]["results"][0]
    unknown = _sarif([_issue()])["runs"][0]["results"][0]

    assert direct["properties"]["dependency"] == "direct"
    assert transitive["properties"]["dependency"] == "transitive"
    assert "dependency" not in unknown["properties"]


def test_an_empty_backlog_is_a_valid_empty_run():
    """A pipeline uploads unconditionally, so "nothing found" has to serialize —
    and it is also what tells the platform to clear what it showed before."""
    document = _sarif([])

    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"] == []


# --- CSV additions ---

def test_the_csv_states_directness_and_the_review_date():
    csv_text = build_issues_csv([
        _issue(is_direct_dependency=True, triage_expires_at=datetime(2026, 12, 1, 8, 0)),
        _issue(is_direct_dependency=False),
        _issue(),
    ])
    lines = csv_text.strip().split("\r\n")

    assert "dependency" in lines[0]
    assert ",direct," in lines[1]
    assert "2026-12-01" in lines[1]
    assert ",transitive," in lines[2]
    # Unknown is blank, not the word "unknown": a column full of "unknown" reads
    # like a finding about the dependency.
    assert ",transitive," not in lines[3] and ",direct," not in lines[3]

"""Translation of Semgrep output into findings, and the rules that keep it honest.

The cases that matter here are not the happy path — that is one dictionary lookup. They
are the three places where a plausible shortcut destroys data or breaks somebody's build:

- `None` must not become `[]`, because `[]` means "analysed, clean" and licenses the
  ingestor to resolve a target's whole SAST backlog;
- a severity outside the application's vocabulary propagates silently through sorting,
  the gate and the SARIF export, so the mapping is a table and not a `.lower()`;
- a quality finding must never be able to fail a CI gate, whatever its severity.
"""
import pytest

from zanshin.services.policy_gate import QUALITY_TYPES
from zanshin.services.sast_service import (
    FINDING_TYPE_QUALITY,
    FINDING_TYPE_SAST,
    SETTING_KEY_SAST_ENABLED,
    SastService,
)


def _result(
    check_id="zanshin-python-eval-exec",
    severity="ERROR",
    category="security",
    confidence="HIGH",
    path="app/main.py",
    line=42,
    message="Appel à eval sur une valeur non littérale",
):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 5},
        "extra": {
            "message": message,
            "severity": severity,
            "metadata": {"category": category, "confidence": confidence},
        },
    }


@pytest.fixture()
def service():
    return SastService()


# --- The security / quality split -----------------------------------------------

def test_a_security_rule_produces_a_sast_finding(service):
    findings = service.build_findings(1, [_result(category="security")])

    assert [f.type for f in findings] == [FINDING_TYPE_SAST]


@pytest.mark.parametrize(
    "category", ["correctness", "best-practice", "performance", "maintainability"]
)
def test_every_other_category_produces_a_quality_finding(service, category):
    findings = service.build_findings(1, [_result(category=category)])

    assert [f.type for f in findings] == [FINDING_TYPE_QUALITY]


def test_a_rule_without_a_category_is_treated_as_quality(service):
    """The safer of the two mistakes: an unclassified rule that could fail somebody's
    build is worse than one that merely sits in the backlog."""
    findings = service.build_findings(1, [_result(category=None)])

    assert [f.type for f in findings] == [FINDING_TYPE_QUALITY]


def test_quality_findings_are_the_type_the_gate_refuses(service):
    """Ties the two halves together: the string this service produces has to be the
    string `policy_gate` excludes, and nothing else checks that they agree."""
    findings = service.build_findings(1, [_result(category="best-practice")])

    assert findings[0].type in QUALITY_TYPES


# --- Severity --------------------------------------------------------------------

@pytest.mark.parametrize(
    "level,expected", [("ERROR", "high"), ("WARNING", "medium"), ("INFO", "low")]
)
def test_semgrep_levels_map_onto_the_application_vocabulary(service, level, expected):
    findings = service.build_findings(1, [_result(severity=level)])

    assert findings[0].severity == expected


def test_an_unknown_level_lands_on_unknown_rather_than_leaking_through(service):
    """`"ERROR".lower()` is `"error"`, which is in no severity list in this codebase: it
    sorts below `negligible`, invents a bucket in the tally, can never meet a gate
    threshold and exports as `warning`. All without raising."""
    from zanshin.services.policy_gate import SEVERITY_ORDER

    findings = service.build_findings(1, [_result(severity="INVENTORY")])

    assert findings[0].severity == "unknown"
    assert findings[0].severity in SEVERITY_ORDER


def test_low_confidence_lowers_the_severity_by_one_notch(service):
    """Downgraded, not dropped. Dropping loses the finding *and* its triage, and brings
    it back as brand new the day the rule's metadata changes."""
    findings = service.build_findings(1, [_result(severity="ERROR", confidence="LOW")])

    assert findings[0].severity == "medium"


def test_a_low_confidence_finding_falls_under_the_default_gate_threshold(service):
    """The point of the downgrade, stated as the behaviour it buys: visible in the
    backlog, unable to break a build."""
    from zanshin.services.policy_gate import DEFAULT_FAIL_ON_SEVERITY, is_at_least

    findings = service.build_findings(1, [_result(severity="ERROR", confidence="LOW")])

    assert not is_at_least(findings[0].severity, DEFAULT_FAIL_ON_SEVERITY)


def test_high_confidence_leaves_the_severity_alone(service):
    findings = service.build_findings(1, [_result(severity="ERROR", confidence="HIGH")])

    assert findings[0].severity == "high"


def test_the_downgrade_stops_at_the_bottom_of_the_scale(service):
    findings = service.build_findings(1, [_result(severity="INFO", confidence="LOW")])

    assert findings[0].severity == "negligible"


# --- "Did not run" versus "found nothing" ----------------------------------------

def test_none_stays_none(service):
    """The distinction the whole design turns on: `None` reaches
    `scanned_types_for(sast_ran=...)` as False, and the backlog is left alone."""
    assert service.build_findings(1, None) is None


def test_an_empty_result_set_is_an_empty_list(service):
    """And this one is the positive claim — analysed, clean — which is what allows past
    findings to be resolved."""
    assert service.build_findings(1, []) == []


# --- The fields a reviewer actually reads ----------------------------------------

def test_the_message_is_carried_on_the_finding(service):
    """Without it the scan panel shows a rule id, a file and a line, and nothing a
    reviewer can act on — which is why `Finding.description` was added."""
    findings = service.build_findings(1, [_result(message="Requête SQL concaténée")])

    assert findings[0].description == "Requête SQL concaténée"


def test_an_empty_message_is_stored_as_null_rather_than_an_empty_string(service):
    findings = service.build_findings(1, [_result(message="   ")])

    assert findings[0].description is None


def test_the_identifier_line_and_source_are_what_the_backlog_keys_on(service):
    findings = service.build_findings(1, [_result(check_id="zanshin-js-eval", line=7)])

    finding = findings[0]
    assert finding.identifier == "zanshin-js-eval"
    assert finding.file_path == "app/main.py"
    assert finding.line == 7
    assert finding.source == "semgrep"


def test_a_leading_slash_never_reaches_the_fingerprint(service):
    """`file_path` is part of an issue's fingerprint, so a path that varies with where
    the scan ran would create a new issue per worker."""
    findings = service.build_findings(1, [_result(path="/app/main.py")])

    assert findings[0].file_path == "app/main.py"


# --- The toggle -------------------------------------------------------------------

class _Settings:
    def __init__(self, values=None):
        self.values = values or {}

    def get_setting(self, key, default=""):
        return self.values.get(key, default)

    def update_setting(self, key, value):
        self.values[key] = value


def test_the_step_is_off_unless_enabled():
    """Off by default because the first run on a mature repository can add hundreds of
    entries to the backlog — that should be a day somebody chose."""
    assert SastService(_Settings()).is_enabled() is False


def test_enabling_writes_the_setting():
    settings = _Settings()

    SastService(settings).set_enabled(True)

    assert settings.values[SETTING_KEY_SAST_ENABLED] == "true"
    assert SastService(settings).is_enabled() is True


def test_a_service_without_settings_reports_disabled_rather_than_raising():
    """Constructed without a database on purpose — the translation half is used where
    there is no session."""
    assert SastService().is_enabled() is False

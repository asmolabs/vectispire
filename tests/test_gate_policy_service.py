"""Tests for the stored gate policy.

Two things carry the feature, and both are easy to get wrong in a way that looks
right: the resolution order (target, then global, then the code's defaults) and the
definition of "stricter". The second is the one that bit during development —
`SEVERITY_ORDER` is worst-first, so a *higher* rank is a *lower* threshold, and an
inverted comparison would have shipped the exact opposite of the feature: a pipeline
free to raise its own threshold to `critical`.
"""
import pytest

from zanshin.repositories.gate_policy_repository import GatePolicyRepository
from zanshin.services.gate_policy_service import (
    SOURCE_BUILT_IN,
    SOURCE_GLOBAL,
    SOURCE_TARGET,
    GatePolicyService,
    harden,
)
from zanshin.services.policy_gate import GatePolicy


@pytest.fixture()
def service(db_session):
    return GatePolicyService(GatePolicyRepository(db_session))


# --- Resolution ---

def test_an_empty_table_behaves_exactly_as_before(service):
    """The gate has to keep working on a database where nothing is configured — which
    is every database the moment this ships."""
    resolved = service.resolve("repository", 1)

    assert resolved.source == SOURCE_BUILT_IN
    assert resolved.policy == GatePolicy()
    assert resolved.version is None


def test_a_global_policy_applies_to_every_target(service):
    service.save_policy(fail_on_severity="medium", actor="alice")

    resolved = service.resolve("repository", 42)

    assert resolved.source == SOURCE_GLOBAL
    assert resolved.policy.fail_on_severity == "medium"
    assert resolved.version == 1


def test_a_target_policy_wins_over_the_global_one(service):
    service.save_policy(fail_on_severity="high", actor="alice")
    service.save_policy(
        target_kind="repository", target_id=7, fail_on_severity="low", actor="alice"
    )

    assert service.resolve("repository", 7).policy.fail_on_severity == "low"
    assert service.resolve("repository", 7).source == SOURCE_TARGET
    # Another target still inherits the global one.
    assert service.resolve("repository", 8).policy.fail_on_severity == "high"


def test_a_target_policy_replaces_rather_than_merges(service):
    """A half-inherited policy is impossible to reason about when a build fails: "this
    repository's rules" has to be readable in one place."""
    service.save_policy(fail_on_severity="high", fail_on_kev=True, include_triaged=True, actor="a")
    service.save_policy(
        target_kind="container", target_id=3, fail_on_severity="critical",
        fail_on_kev=False, actor="a",
    )

    policy = service.resolve("container", 3).policy

    assert policy.fail_on_severity == "critical"
    assert policy.fail_on_kev is False
    # Not inherited from the global policy.
    assert policy.include_triaged is False


def test_the_kinds_are_distinct(service):
    """Ids are per-table, so a policy for repository 1 must not govern container 1."""
    service.save_policy(target_kind="repository", target_id=1, fail_on_severity="low", actor="a")

    assert service.resolve("container", 1).source == SOURCE_BUILT_IN


# --- Versioning ---

def test_saving_creates_a_version_instead_of_overwriting(service):
    """A policy is a security decision; overwriting it would erase the decision along
    with its author."""
    service.save_policy(fail_on_severity="high", actor="alice", note="départ")
    second = service.save_policy(fail_on_severity="medium", actor="bob", note="durci")

    assert second.version == 2
    history = service.history()
    assert [p.version for p in history] == [2, 1]
    assert [p.created_by for p in history] == ["bob", "alice"]
    assert history[1].note == "départ"


def test_only_one_version_is_active_per_scope(service):
    service.save_policy(fail_on_severity="high", actor="a")
    service.save_policy(fail_on_severity="medium", actor="a")

    active = [p for p in service.history() if p.is_active]

    assert len(active) == 1
    assert active[0].fail_on_severity == "medium"


def test_the_database_refuses_two_active_policies_for_one_scope(db_session, service):
    """Enforced by a constraint and not only by the service: two active rows would
    make the verdict depend on row order, which nobody would notice until it
    mattered."""
    from sqlalchemy.exc import IntegrityError

    from zanshin.models.gate_policy import StoredGatePolicy

    service.save_policy(fail_on_severity="high", actor="a")
    db_session.add(StoredGatePolicy(version=99, is_active=True, fail_on_kev=True,
                                    fixable_only=False, include_triaged=False,
                                    include_ai_review=False))

    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_deleting_a_target_policy_falls_back_to_the_global_one(service):
    service.save_policy(fail_on_severity="high", actor="a")
    service.save_policy(target_kind="repository", target_id=5, fail_on_severity="low", actor="a")
    assert service.resolve("repository", 5).source == SOURCE_TARGET

    assert service.delete_target_policy("repository", 5) is True

    assert service.resolve("repository", 5).source == SOURCE_GLOBAL
    # The history survives: it is the record of what judged past builds.
    assert len(service.history("repository", 5)) == 1


def test_the_global_policy_cannot_be_deleted(service):
    service.save_policy(fail_on_severity="high", actor="a")

    with pytest.raises(ValueError, match="ne peut pas être supprimée"):
        service.delete_target_policy(None, None)


# --- Validation ---

def test_an_unknown_severity_is_refused(service):
    with pytest.raises(ValueError, match="Sévérité inconnue"):
        service.save_policy(fail_on_severity="catastrophique", actor="a")


def test_no_severity_rule_is_a_valid_policy(service):
    """Legitimate for a policy that gates only on known-exploited vulnerabilities."""
    service.save_policy(fail_on_severity=None, fail_on_kev=True, actor="a")

    assert service.resolve().policy.fail_on_severity is None


def test_a_half_specified_scope_is_refused(service):
    with pytest.raises(ValueError, match="Portée invalide"):
        service.save_policy(target_kind="repository", actor="a")


# --- Hardening ---

BASE = GatePolicy(fail_on_severity="medium", fail_on_kev=True, fixable_only=False)


def test_an_absent_field_is_not_an_opinion():
    """`requested` holds only what the caller sent. Without that distinction, every
    caller who omits a field would be told their request was refused, on every call."""
    policy, ignored = harden(BASE, {})

    assert policy == BASE
    assert ignored == []


def test_a_lower_threshold_is_accepted_because_it_is_stricter():
    """`SEVERITY_ORDER` is worst-first, so `low` catches more than `medium`. Getting
    this comparison backwards is the mistake that would invert the whole feature."""
    policy, ignored = harden(BASE, {"fail_on_severity": "low"})

    assert policy.fail_on_severity == "low"
    assert ignored == []


def test_a_higher_threshold_is_refused_and_reported():
    policy, ignored = harden(BASE, {"fail_on_severity": "critical"})

    assert policy.fail_on_severity == "medium"
    assert ignored == ["fail_on_severity"]


def test_removing_the_severity_rule_is_refused():
    policy, ignored = harden(BASE, {"fail_on_severity": None})

    assert policy.fail_on_severity == "medium"
    assert ignored == ["fail_on_severity"]


def test_adding_a_severity_rule_where_there_was_none_is_accepted():
    policy, ignored = harden(GatePolicy(fail_on_severity=None), {"fail_on_severity": "high"})

    assert policy.fail_on_severity == "high"
    assert ignored == []


def test_turning_off_the_kev_rule_is_refused():
    policy, ignored = harden(BASE, {"fail_on_kev": False})

    assert policy.fail_on_kev is True
    assert ignored == ["fail_on_kev"]


def test_asking_for_fixable_only_is_refused():
    """The field a naive "take the True" merge gets wrong: `True` fails on *fewer*
    things, and it is the most tempting one to set — it silently tolerates an
    actively-exploited vulnerability with no patch."""
    policy, ignored = harden(BASE, {"fixable_only": True})

    assert policy.fixable_only is False
    assert ignored == ["fixable_only"]


def test_switching_fixable_only_off_is_accepted():
    policy, ignored = harden(GatePolicy(fixable_only=True), {"fixable_only": False})

    assert policy.fixable_only is False
    assert ignored == []


@pytest.mark.parametrize("field", ["include_triaged", "include_ai_review"])
def test_counting_more_issues_is_accepted(field):
    policy, ignored = harden(BASE, {field: True})

    assert getattr(policy, field) is True
    assert ignored == []


def test_several_relaxations_are_all_reported():
    policy, ignored = harden(BASE, {"fail_on_severity": "critical", "fail_on_kev": False})

    assert policy == BASE
    assert set(ignored) == {"fail_on_severity", "fail_on_kev"}


def test_the_resolved_policy_describes_where_it_came_from(service):
    """A pipeline that fails needs to know whose rules failed it — otherwise the first
    reaction is to widen its own settings, which now changes nothing."""
    service.save_policy(fail_on_severity="high", actor="a")

    assert "globale v1" in service.resolve("repository", 1).description
    service.save_policy(target_kind="repository", target_id=1, fail_on_severity="low", actor="a")
    assert "de la cible v1" in service.resolve("repository", 1).description

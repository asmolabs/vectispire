"""Tests for raw-payload retention.

The policy has to be trustworthy in two directions: it must actually bound growth
(the database went to 18 MB for thirteen scans), and it must never drop something
an operator would reach for — which means the newest scans of every target, and
never the normalized data that serves as the durable record.
"""
from datetime import timedelta

import pytest

from zanshin.clock import utcnow
from zanshin.models.finding import Finding
from zanshin.models.scan import Scan
from zanshin.models.setting import Setting
from zanshin.services.retention_service import (
    SETTING_KEY_RETENTION_KEEP_PER_TARGET,
    SETTING_KEY_RETENTION_MAX_AGE_DAYS,
    RetentionService,
)

BIG_SBOM = {"artifacts": [{"name": f"pkg-{i}"} for i in range(200)]}
CVES = {"matches": [{"vulnerability": {"id": "CVE-1"}}]}


@pytest.fixture()
def service(settings_service, setting_repository):
    def _build(keep=None, max_age=None):
        if keep is not None:
            setting_repository.save(
                Setting(key=SETTING_KEY_RETENTION_KEEP_PER_TARGET, value=str(keep))
            )
        if max_age is not None:
            setting_repository.save(
                Setting(key=SETTING_KEY_RETENTION_MAX_AGE_DAYS, value=str(max_age))
            )
        return RetentionService(settings_service)

    return _build


def _scan(db, *, repo_id=None, container_id=None, age_days=0, payload=True):
    scan = Scan(
        repo_id=repo_id,
        container_id=container_id,
        branch="main",
        status="completed",
        findings_count=1,
        summary={"high": 1, "total": 1},
        sbom=BIG_SBOM if payload else None,
        cves=CVES if payload else None,
        created_at=utcnow() - timedelta(days=age_days),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


# --- What gets pruned ---

def test_the_newest_scans_of_a_target_are_never_pruned(db_session, service, make_repository):
    """A retention policy that dropped the most recent payloads would be useless
    for the one thing they are for."""
    repo = make_repository()
    svc = service(keep=2, max_age=1)
    recent = [_scan(db_session, repo_id=repo.id, age_days=age) for age in (10, 20)]
    old = _scan(db_session, repo_id=repo.id, age_days=30)

    prunable = svc.find_prunable(db_session)

    assert [s.id for s in prunable] == [old.id]
    assert all(s.sbom is not None for s in recent)


def test_age_alone_never_prunes_a_rarely_scanned_target(db_session, service, make_repository):
    """A repository scanned twice a year keeps its payloads: they are old, but
    they are also all it has. Age alone would drop them."""
    repo = make_repository()
    svc = service(keep=2, max_age=30)
    _scan(db_session, repo_id=repo.id, age_days=400)
    _scan(db_session, repo_id=repo.id, age_days=500)

    assert svc.find_prunable(db_session) == []


def test_the_count_window_alone_never_prunes_something_recent(db_session, service, make_repository):
    """A target scanned hourly pushes rows out of the count window within the
    hour; the age floor is what keeps today's scans readable."""
    repo = make_repository()
    svc = service(keep=1, max_age=30)
    _scan(db_session, repo_id=repo.id, age_days=0)
    _scan(db_session, repo_id=repo.id, age_days=1)  # outside keep=1, but recent

    assert svc.find_prunable(db_session) == []


def test_the_window_is_counted_per_target(db_session, service, make_repository, make_container):
    """Ten scans of one image must not consume another target's allowance."""
    repo = make_repository()
    container = make_container()
    svc = service(keep=1, max_age=1)
    _scan(db_session, repo_id=repo.id, age_days=5)
    repo_old = _scan(db_session, repo_id=repo.id, age_days=6)
    _scan(db_session, container_id=container.id, age_days=5)
    container_old = _scan(db_session, container_id=container.id, age_days=6)

    prunable = {s.id for s in svc.find_prunable(db_session)}

    assert prunable == {repo_old.id, container_old.id}


def test_zero_in_both_settings_disables_pruning(db_session, service, make_repository):
    repo = make_repository()
    svc = service(keep=0, max_age=0)
    _scan(db_session, repo_id=repo.id, age_days=999)

    assert svc.is_enabled() is False
    assert svc.find_prunable(db_session) == []
    assert svc.prune(db_session, vacuum=False).scans_pruned == 0


def test_a_non_integer_setting_falls_back_to_the_default(db_session, service, setting_repository):
    setting_repository.save(Setting(key=SETTING_KEY_RETENTION_KEEP_PER_TARGET, value="beaucoup"))
    svc = service()

    assert svc.keep_per_target() == 10  # the documented default


def test_scans_without_a_payload_are_ignored(db_session, service, make_repository):
    """Already-pruned rows must not be re-walked forever; the column check is what
    keeps this cheap enough to run on a timer."""
    repo = make_repository()
    svc = service(keep=0, max_age=1)
    _scan(db_session, repo_id=repo.id, age_days=999, payload=False)

    assert svc.find_prunable(db_session) == []


# --- What pruning does, and does not, destroy ---

def test_pruning_drops_the_blobs_and_keeps_everything_else(db_session, service, make_repository):
    """The normalized projection *is* the durable record — that was the point of
    building it — so pruning a blob must cost no history."""
    repo = make_repository()
    svc = service(keep=0, max_age=1)
    scan = _scan(db_session, repo_id=repo.id, age_days=30)
    db_session.add(
        Finding(scan_id=scan.id, type="vulnerability", identifier="CVE-1", severity="high",
                source="grype", cvss_score=7.5, fix_versions="1.2.3")
    )
    db_session.commit()

    result = svc.prune(db_session, vacuum=False)

    db_session.refresh(scan)
    assert result.scans_pruned == 1
    assert result.bytes_freed > 0
    assert scan.sbom is None and scan.cves is None
    # Everything the UI and the API actually read survives.
    assert scan.summary == {"high": 1, "total": 1}
    assert scan.findings_count == 1
    assert scan.status == "completed"
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(findings) == 1
    assert findings[0].cvss_score == 7.5
    assert findings[0].fix_versions == "1.2.3"


def test_pruning_nothing_is_a_no_op(db_session, service, make_repository):
    repo = make_repository()
    svc = service(keep=10, max_age=90)
    _scan(db_session, repo_id=repo.id, age_days=1)

    assert svc.prune(db_session, vacuum=False) == (0, 0)


def test_pruning_is_idempotent(db_session, service, make_repository):
    repo = make_repository()
    svc = service(keep=0, max_age=1)
    _scan(db_session, repo_id=repo.id, age_days=30)

    first = svc.prune(db_session, vacuum=False)
    second = svc.prune(db_session, vacuum=False)

    assert first.scans_pruned == 1
    assert second.scans_pruned == 0

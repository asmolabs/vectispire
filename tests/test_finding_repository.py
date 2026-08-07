import pytest

from zanshin.models.finding import Finding


def _make_finding(scan_id, finding_type="vulnerability"):
    return Finding(scan_id=scan_id, type=finding_type, identifier="X", source="grype")


@pytest.fixture()
def scan_ids(db_session, make_repository, make_scan):
    """Two real scans to attach findings to.

    These tests used to pass literal `scan_id=1` and `scan_id=2` for scans that did not
    exist — which only worked because SQLite was not enforcing the foreign keys it
    declared. Now that it does, the fixture provides real ones: a small illustration of
    the class of bug the enforcement prevents.
    """
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    second = make_scan(repo_id=repo.id, status="completed")
    return first.id, second.id


def test_find_all_by_scan_id(db_session, finding_repository, scan_ids):
    one, two = scan_ids
    db_session.add_all([_make_finding(one), _make_finding(one), _make_finding(two)])
    db_session.commit()

    assert len(finding_repository.find_all_by_scan_id(one)) == 2
    assert len(finding_repository.find_all_by_scan_id(two)) == 1
    assert finding_repository.find_all_by_scan_id(999) == []


def test_find_all_by_scan_id_and_type(db_session, finding_repository, scan_ids):
    one, _two = scan_ids
    db_session.add_all([
        _make_finding(one, finding_type="vulnerability"),
        _make_finding(one, finding_type="secret"),
        _make_finding(one, finding_type="secret"),
    ])
    db_session.commit()

    secrets = finding_repository.find_all_by_scan_id_and_type(one, "secret")
    vulns = finding_repository.find_all_by_scan_id_and_type(one, "vulnerability")

    assert len(secrets) == 2
    assert len(vulns) == 1


def test_count_by_scan_ids_and_type(db_session, finding_repository, scan_ids):
    one, two = scan_ids
    db_session.add_all([
        _make_finding(one, finding_type="secret"),
        _make_finding(one, finding_type="secret"),
        _make_finding(two, finding_type="secret"),
        _make_finding(one, finding_type="vulnerability"),
    ])
    db_session.commit()

    counts = finding_repository.count_by_scan_ids_and_type([one, two, 999], "secret")

    assert counts == {one: 2, two: 1}
    assert 999 not in counts


def test_count_by_scan_ids_and_type_counts_every_observation(
    db_session, finding_repository, scan_ids
):
    """No state filter any more: a finding *is* an observation of one scan, and
    whether the problem is still open or has been triaged belongs to its
    `Issue`. This used to filter on `Finding.status`, which was written once as
    "open" and never updated — so the filter did nothing while implying it did."""
    one, _two = scan_ids
    db_session.add_all([
        _make_finding(one, finding_type="secret"),
        _make_finding(one, finding_type="secret"),
    ])
    db_session.commit()

    counts = finding_repository.count_by_scan_ids_and_type([one], "secret")

    assert counts == {one: 2}


def test_count_by_scan_ids_and_type_with_empty_list(finding_repository):
    assert finding_repository.count_by_scan_ids_and_type([], "secret") == {}


def test_save_persists_and_returns_finding(finding_repository, scan_ids):
    one, _two = scan_ids
    saved = finding_repository.save(_make_finding(one))
    assert saved.id is not None

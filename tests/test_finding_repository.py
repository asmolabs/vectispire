from zanshin.models.finding import Finding


def _make_finding(scan_id, finding_type="vulnerability", status="open"):
    return Finding(scan_id=scan_id, type=finding_type, status=status, identifier="X", source="grype")


def test_find_all_by_scan_id(db_session, finding_repository):
    db_session.add_all([_make_finding(1), _make_finding(1), _make_finding(2)])
    db_session.commit()

    assert len(finding_repository.find_all_by_scan_id(1)) == 2
    assert len(finding_repository.find_all_by_scan_id(2)) == 1
    assert finding_repository.find_all_by_scan_id(999) == []


def test_find_all_by_scan_id_and_type(db_session, finding_repository):
    db_session.add_all([
        _make_finding(1, finding_type="vulnerability"),
        _make_finding(1, finding_type="secret"),
        _make_finding(1, finding_type="secret"),
    ])
    db_session.commit()

    secrets = finding_repository.find_all_by_scan_id_and_type(1, "secret")
    vulns = finding_repository.find_all_by_scan_id_and_type(1, "vulnerability")

    assert len(secrets) == 2
    assert len(vulns) == 1


def test_find_all_open(db_session, finding_repository):
    db_session.add_all([_make_finding(1, status="open"), _make_finding(1, status="ignored")])
    db_session.commit()

    open_findings = finding_repository.find_all_open()

    assert len(open_findings) == 1
    assert open_findings[0].status == "open"


def test_count_by_scan_ids_and_type(db_session, finding_repository):
    db_session.add_all([
        _make_finding(1, finding_type="secret"),
        _make_finding(1, finding_type="secret"),
        _make_finding(2, finding_type="secret"),
        _make_finding(1, finding_type="vulnerability"),
    ])
    db_session.commit()

    counts = finding_repository.count_by_scan_ids_and_type([1, 2, 999], "secret")

    assert counts == {1: 2, 2: 1}
    assert 999 not in counts


def test_count_by_scan_ids_and_type_only_counts_open(db_session, finding_repository):
    db_session.add_all([
        _make_finding(1, finding_type="secret", status="open"),
        _make_finding(1, finding_type="secret", status="ignored"),
    ])
    db_session.commit()

    counts = finding_repository.count_by_scan_ids_and_type([1], "secret")

    assert counts == {1: 1}


def test_count_by_scan_ids_and_type_with_empty_list(finding_repository):
    assert finding_repository.count_by_scan_ids_and_type([], "secret") == {}


def test_save_persists_and_returns_finding(finding_repository):
    saved = finding_repository.save(_make_finding(1))
    assert saved.id is not None

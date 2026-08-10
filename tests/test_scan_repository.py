"""Tests for the column-only scan queries added to `ScanRepository`.

These replace the "walk `Repository.scans` / `Container.scans` and sort in
Python" pattern the list screens used, which — with the relationships declared
`lazy="joined"` — loaded every scan's `sbom`/`cves` JSON blob just to render a
status column.
"""
from datetime import datetime, timedelta

from zanshin.clock import utcnow

from zanshin.models.scan import Scan


def _add_scan(db_session, *, repo_id=None, container_id=None, created_at=None,
              status="completed", summary=None, findings_count=0, sbom=None, cves=None):
    scan = Scan(
        repo_id=repo_id,
        container_id=container_id,
        branch="main",
        status=status,
        findings_count=findings_count,
        summary=summary,
        sbom=sbom,
        cves=cves,
        created_at=created_at or utcnow(),
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan


def test_find_latest_summary_by_repository_ids_returns_the_newest_per_repo(
    db_session, scan_repository, make_repository
):
    older, newer = datetime(2026, 1, 1, 8, 0), datetime(2026, 1, 2, 8, 0)
    repo_a = make_repository(url="git@example.com:org/a.git")
    repo_b = make_repository(url="git@example.com:org/b.git")
    _add_scan(db_session, repo_id=repo_a.id, created_at=older, status="failed")
    expected_a = _add_scan(db_session, repo_id=repo_a.id, created_at=newer, status="completed")
    expected_b = _add_scan(db_session, repo_id=repo_b.id, created_at=older)

    latest = scan_repository.find_latest_summary_by_repository_ids([repo_a.id, repo_b.id])

    assert set(latest) == {repo_a.id, repo_b.id}
    assert latest[repo_a.id].id == expected_a.id
    assert latest[repo_a.id].status == "completed"
    assert latest[repo_b.id].id == expected_b.id


def test_find_latest_summary_skips_repositories_without_scans(scan_repository, make_repository):
    repo = make_repository()
    assert scan_repository.find_latest_summary_by_repository_ids([repo.id]) == {}


def test_find_latest_summary_with_no_ids_does_not_query(scan_repository):
    assert scan_repository.find_latest_summary_by_repository_ids([]) == {}
    assert scan_repository.find_latest_summary_by_container_ids([]) == {}


def test_find_latest_summary_falls_back_to_id_when_timestamps_tie(
    db_session, scan_repository, make_repository
):
    """Two scans of the same repo can share a timestamp (legacy rows, or a
    fast rescan); the higher id is the later one."""
    same_moment = datetime(2026, 1, 1, 8, 0)
    repo = make_repository()
    _add_scan(db_session, repo_id=repo.id, created_at=same_moment, status="failed")
    later = _add_scan(db_session, repo_id=repo.id, created_at=same_moment, status="completed")

    latest = scan_repository.find_latest_summary_by_repository_ids([repo.id])

    assert latest[repo.id].id == later.id


def test_summary_carries_what_the_lists_display_and_nothing_more(
    db_session, scan_repository, make_repository
):
    repo = make_repository()
    _add_scan(
        db_session,
        repo_id=repo.id,
        findings_count=7,
        summary={"critical": 1, "high": 2, "total": 7},
        # Deliberately present: the point of these queries is that this never
        # gets loaded.
        sbom={"artifacts": ["huge"]},
        cves={"matches": ["huge"]},
    )

    summary = scan_repository.find_latest_summary_by_repository_ids([repo.id])[repo.id]

    assert summary.findings_count == 7
    assert summary.summary["critical"] == 1
    assert not hasattr(summary, "sbom")
    assert not hasattr(summary, "cves")


def test_find_latest_summary_by_container_ids(db_session, scan_repository, make_container):
    container = make_container(image_name="nginx")
    _add_scan(db_session, container_id=container.id, created_at=datetime(2026, 1, 1))
    expected = _add_scan(db_session, container_id=container.id, created_at=datetime(2026, 2, 1))

    latest = scan_repository.find_latest_summary_by_container_ids([container.id])

    assert latest[container.id].id == expected.id


def test_find_summaries_by_repository_id_is_newest_first(
    db_session, scan_repository, make_repository
):
    repo = make_repository()
    other_repo = make_repository(url="git@example.com:org/other.git")
    oldest = _add_scan(db_session, repo_id=repo.id, created_at=datetime(2026, 1, 1))
    newest = _add_scan(db_session, repo_id=repo.id, created_at=datetime(2026, 3, 1))
    middle = _add_scan(db_session, repo_id=repo.id, created_at=datetime(2026, 2, 1))
    _add_scan(db_session, repo_id=other_repo.id, created_at=datetime(2026, 4, 1))

    summaries = scan_repository.find_summaries_by_repository_id(repo.id)

    assert [s.id for s in summaries] == [newest.id, middle.id, oldest.id]


def test_find_history_rows_resolves_both_kinds_of_target(
    db_session, scan_repository, make_repository, make_container
):
    repo = make_repository(url="git@example.com:org/app.git")
    repo.name = "App"
    db_session.commit()
    container = make_container(image_name="nginx", tag="1.25", registry="registry.internal")
    repo_scan = _add_scan(db_session, repo_id=repo.id, created_at=datetime(2026, 1, 1))
    container_scan = _add_scan(db_session, container_id=container.id, created_at=datetime(2026, 2, 1))

    rows = scan_repository.find_history_rows()

    assert [row.scan.id for row in rows] == [container_scan.id, repo_scan.id]

    container_row, repo_row = rows
    assert container_row.image_string == "registry.internal/nginx:1.25"
    assert container_row.repo_name is None
    assert repo_row.repo_name == "App"
    assert repo_row.repo_url == "git@example.com:org/app.git"
    assert repo_row.image_string is None


def test_find_history_rows_builds_image_string_without_a_registry(
    db_session, scan_repository, make_container
):
    container = make_container(image_name="nginx", tag="latest", registry=None)
    _add_scan(db_session, container_id=container.id)

    row = scan_repository.find_history_rows()[0]

    assert row.image_string == "nginx:latest"


def test_find_all_created_at_returns_one_timestamp_per_scan(
    db_session, scan_repository, make_repository, make_container
):
    """Feeds the dashboard's activity histogram; covers both kinds of target,
    since it deliberately doesn't filter on one. (The null-skipping in the
    query is defensive only — `scan.created_at` is NOT NULL in the current
    schema, so it can't be exercised through the ORM.)"""
    repo = make_repository()
    container = make_container()
    _add_scan(db_session, repo_id=repo.id, created_at=datetime(2026, 1, 1))
    _add_scan(db_session, container_id=container.id, created_at=datetime(2026, 1, 2))

    timestamps = scan_repository.find_all_created_at()

    assert sorted(timestamps) == [datetime(2026, 1, 1), datetime(2026, 1, 2)]


def test_delete_by_id_removes_the_scan(db_session, scan_repository, make_repository):
    """The scan-history UI has always called this; it didn't exist, so
    deleting a scan raised AttributeError behind a generic error toast."""
    repo = make_repository()
    scan = _add_scan(db_session, repo_id=repo.id)

    assert scan_repository.delete_by_id(scan.id) is True
    assert scan_repository.find_by_id(scan.id) is None


def test_delete_by_id_of_an_unknown_scan_is_false(scan_repository):
    assert scan_repository.delete_by_id(4242) is False


def test_deleting_a_repository_still_cascades_to_its_scans(
    db_session, scan_repository, repository_repository, make_repository
):
    """Dropping `lazy="joined"` must not weaken the delete cascade."""
    repo = make_repository()
    scan = _add_scan(db_session, repo_id=repo.id)
    scan_id = scan.id

    repository_repository.delete_by_id(repo.id)

    # Expunged first: `find_by_id` on an instance still in the identity map raises
    # `ObjectDeletedError` once the row is gone, which is the ORM reporting that the
    # cascade worked rather than a failure.
    db_session.expunge_all()
    assert scan_repository.find_by_id(scan_id) is None


def test_recent_scans_ordering_survives_a_naive_utcnow_mix(
    db_session, scan_repository, make_repository
):
    """Legacy rows and freshly created ones coexist; ordering must not depend
    on which code path wrote the timestamp."""
    repo = make_repository()
    now = utcnow()
    old = _add_scan(db_session, repo_id=repo.id, created_at=now - timedelta(days=30))
    recent = _add_scan(db_session, repo_id=repo.id, created_at=now)

    summaries = scan_repository.find_summaries_by_repository_id(repo.id)

    assert [s.id for s in summaries] == [recent.id, old.id]


def test_count_by_queue_state_counts_queued_and_running(
    db_session, scan_repository, make_repository
):
    """Regression: this method used `func.count` without importing `func`, so every
    call raised `NameError`.

    It was invisible because its only caller is the Paramètres loader, inside a
    `try` that turns any exception into a toast — so the symptom was not a crash but
    a settings screen showing defaults instead of stored values, every field after
    this one left unloaded. A type checker named it in one pass; no test did.
    """
    from zanshin.services.scan_queue import STATUS_QUEUED, STATUS_RUNNING

    repo = make_repository()
    _add_scan(db_session, repo_id=repo.id, status=STATUS_QUEUED)
    _add_scan(db_session, repo_id=repo.id, status=STATUS_QUEUED)
    _add_scan(db_session, repo_id=repo.id, status=STATUS_RUNNING)
    _add_scan(db_session, repo_id=repo.id, status="completed")

    assert scan_repository.count_by_queue_state() == {"queued": 2, "running": 1}


def test_count_by_queue_state_reports_zero_rather_than_an_empty_mapping(scan_repository):
    """The settings screen reads both keys unconditionally."""
    assert scan_repository.count_by_queue_state() == {"queued": 0, "running": 0}

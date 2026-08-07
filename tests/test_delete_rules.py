"""Tests for what happens to a row when the thing it points at is deleted.

These behaviours were previously undefined in a specific and dangerous way: the cascades
were ORM-side only, and SQLite ignores the foreign keys it declares. So a delete that
quietly orphaned rows on a developer's machine raised on a server, and the difference
would have been found in production.

Each test below states the rule and why it is that rule rather than the other one. They
run on SQLite here — where the pragma is now enabled, so the behaviour is the real one —
and the same deletes are exercised against PostgreSQL and MySQL in
`test_delete_rules_backends.py`, which is where "the database enforces this" is actually
proved.
"""
import pytest

from zanshin.models.ai_review_result import AiReviewResult
from zanshin.models.finding import Finding
from zanshin.models.issue import Issue
from zanshin.models.scan import Scan

_next_fingerprint = iter(range(1, 100_000))


def _gone(db, model, primary_key) -> bool:
    """Whether a row is really gone.

    `Session.get` on an instance still in the identity map raises
    `ObjectDeletedError` when the row has disappeared underneath it — which is the ORM
    reporting that the *database* cascaded, not a failure. Expunging first asks the
    question of the database instead of the session.
    """
    db.expunge_all()
    return db.get(model, primary_key) is None


@pytest.fixture()
def target(db_session, make_repository, make_scan):
    """A repository with a scan, a finding, an issue linking the two, and a review."""
    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")
    issue = Issue(
        repo_id=repo.id,
        fingerprint=f"fp-{next(_next_fingerprint)}",
        type="vulnerability",
        identifier="CVE-2024-0001",
        severity="high",
        state="open",
        is_kev=False,
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
    )
    db_session.add(issue)
    db_session.commit()

    finding = Finding(
        scan_id=scan.id,
        type="vulnerability",
        severity="high",
        identifier="CVE-2024-0001",
        source="grype",
        issue_id=issue.id,
    )
    review = AiReviewResult(
        scan_id=scan.id, model="test", prompt="p", response="r", status="completed"
    )
    db_session.add_all([finding, review])
    db_session.commit()
    return repo, scan, issue, finding, review


def test_sqlite_actually_enforces_foreign_keys_now(db_session):
    """The premise of every test below. SQLite parses `REFERENCES` and then ignores it
    unless asked, which is why these rules could be wrong for months without anything
    noticing."""
    from sqlalchemy import text

    assert db_session.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_an_invalid_reference_is_refused(db_session):
    from sqlalchemy.exc import IntegrityError

    db_session.add(Finding(scan_id=999_999, type="vulnerability", severity="high", source="grype"))

    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# --- CASCADE: the row cannot exist without its parent ---

def test_deleting_a_target_takes_its_scans_and_issues(db_session, target):
    repo, scan, issue, finding, review = target

    scan_id, issue_id, finding_id, review_id = scan.id, issue.id, finding.id, review.id

    db_session.delete(repo)
    db_session.commit()

    assert _gone(db_session, Scan, scan_id)
    assert _gone(db_session, Issue, issue_id)
    # The finding went with its scan, not with its issue.
    assert _gone(db_session, Finding, finding_id)
    assert _gone(db_session, AiReviewResult, review_id)


def test_deleting_a_scan_takes_its_findings_and_review(db_session, target):
    _repo, scan, issue, finding, review = target

    finding_id, review_id, issue_id = finding.id, review.id, issue.id

    db_session.delete(scan)
    db_session.commit()

    assert _gone(db_session, Finding, finding_id)
    assert _gone(db_session, AiReviewResult, review_id)
    # But not the issue: see the next test.
    assert db_session.get(Issue, issue_id) is not None


def test_deleting_a_container_takes_its_scans(db_session, make_container, make_scan):
    image = make_container()
    scan = make_scan(container_id=image.id, status="completed")

    scan_id = scan.id

    db_session.delete(image)
    db_session.commit()

    assert _gone(db_session, Scan, scan_id)


# --- SET NULL: the row outlives the reference ---

def test_an_issue_survives_the_scan_that_saw_it(db_session, target):
    """Issues outlive scans by design: retention prunes old scans while the issue keeps
    its history. There is no ORM relationship from `Scan` back to these columns, so
    SQLAlchemy could not have cleared them — on PostgreSQL, deleting a scan simply
    failed."""
    _repo, scan, issue, _finding, _review = target
    issue_id = issue.id

    db_session.delete(scan)
    db_session.commit()
    db_session.expunge_all()
    issue = db_session.get(Issue, issue_id)

    assert issue.first_seen_scan_id is None
    assert issue.last_seen_scan_id is None
    # And everything that makes the issue worth keeping is untouched.
    assert issue.identifier == "CVE-2024-0001"
    assert issue.state == "open"


def test_a_finding_survives_the_issue_it_was_folded_into(db_session, target):
    """The hole this was written to close: `Issue.findings` had no cascade at all. SET
    NULL and not CASCADE because the observation genuinely happened — only its
    attachment to an issue goes away."""
    _repo, _scan, issue, finding, _review = target
    finding_id = finding.id

    db_session.delete(issue)
    db_session.commit()
    db_session.expunge_all()
    finding = db_session.get(Finding, finding_id)

    assert finding.id is not None
    assert finding.issue_id is None
    assert finding.identifier == "CVE-2024-0001"


def test_deleting_an_ssh_key_does_not_delete_the_repositories_using_it(
    db_session, make_repository, encryption_service
):
    """They stay, un-clonable until given another key. Cascading here would delete a
    project's entire history because somebody rotated a credential."""
    from zanshin.repositories.ssh_key_repository import SSHKeyRepository
    from zanshin.services.ssh_key_service import SSHKeyService

    key = SSHKeyService(SSHKeyRepository(db_session), encryption_service).create_key(
        name="deploy", private_key="-----BEGIN KEY-----"
    )
    repo = make_repository()
    repo.ssh_key_id = key.id
    db_session.commit()

    repo_id = repo.id
    db_session.delete(key)
    db_session.commit()
    db_session.expunge_all()
    repo = db_session.get(type(repo), repo_id)

    assert repo.id is not None
    assert repo.ssh_key_id is None


# --- The paths the application actually takes ---

def test_the_repository_service_delete_still_works(db_session, make_repository, make_scan):
    """The delete a user performs from the Depots page, now with the database enforcing
    the constraints the models declare."""
    from zanshin.repositories.repository_repository import RepositoryRepository
    from zanshin.repositories.scan_repository import ScanRepository
    from zanshin.services.repository_service import RepositoryService

    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")
    db_session.add_all([
        Finding(scan_id=scan.id, type="vulnerability", severity="high", source="grype"),
        Issue(
            repo_id=repo.id, fingerprint=f"fp-{next(_next_fingerprint)}", type="vulnerability",
            severity="high", state="open", is_kev=False, first_seen_scan_id=scan.id,
        ),
    ])
    db_session.commit()

    service = RepositoryService(RepositoryRepository(db_session), ScanRepository(db_session))
    service.delete_by_id(repo.id)

    assert RepositoryRepository(db_session).find_by_id(repo.id) is None
    assert db_session.query(Scan).filter(Scan.repo_id == repo.id).count() == 0


def test_deleting_a_scan_through_its_repository_layer_works(db_session, make_repository, make_scan):
    """`ScanRepository.delete_by_id` is what the UI's "delete this scan" calls, and it is
    the path that would have failed on a server database."""
    from zanshin.repositories.scan_repository import ScanRepository

    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")
    db_session.add(
        Issue(
            repo_id=repo.id, fingerprint=f"fp-{next(_next_fingerprint)}", type="vulnerability",
            severity="high", state="open", is_kev=False,
            first_seen_scan_id=scan.id, last_seen_scan_id=scan.id,
        )
    )
    db_session.commit()

    assert ScanRepository(db_session).delete_by_id(scan.id) is True
    assert db_session.query(Issue).count() == 1


def test_retention_still_prunes(db_session, make_repository, make_scan, settings_service):
    """Retention updates payloads rather than deleting rows, so it should be unaffected —
    asserted rather than assumed, because it is the job that touches the most scans."""
    from zanshin.services.retention_service import RetentionService

    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")
    scan.sbom = {"artifacts": []}
    scan.cves = {"matches": []}
    db_session.commit()

    RetentionService(settings_service).prune(db_session, vacuum=False)

    assert db_session.get(Scan, scan.id) is not None

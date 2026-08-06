from typing import List
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan
from zanshin.repositories.repository_repository import RepositoryRepository
from zanshin.repositories.scan_repository import ScanRepository
from zanshin.clock import utcnow
from zanshin.services.git_url import validate_repo_url
from zanshin.services.scan_queue import dispatch


class ScanAlreadyRunningError(RuntimeError):
    """A scan of this target is already pending or running.

    A `RuntimeError` subclass so the existing UI and API error handling reports it
    unchanged, and distinguishable for the API, which answers 409 rather than 404.
    """

# The thread pool and the concurrency limit both live in `scan_queue` now: the pool
# used to *be* the queue, which meant a restart lost everything waiting in it and the
# limit could only be changed by restarting the application. Re-exported here because
# tests and older call sites still reach for `repository_service.executor`.
from zanshin.services.scan_queue import executor  # noqa: F401

class RepositoryService:
    def __init__(self, repository_repository: RepositoryRepository, scan_repository: ScanRepository):
        """No `scan_processor` any more, and that absence is the point.

        This service *queues* a scan; it does not run one. The dispatcher resolves the
        processor when it claims a row, because it has to be able to run a scan that
        was queued by something else — a scheduler tick, another request, or the
        process that died before the restart. A processor injected here could only ever
        run the scans this instance happened to create.
        """
        self.repository_repository = repository_repository
        self.scan_repository = scan_repository

    def find_all(self) -> List[ZanshinRepository]:
        return self.repository_repository.find_all()

    def find_by_id(self, repo_id: int) -> ZanshinRepository:
        return self.repository_repository.find_by_id(repo_id)

    def save(self, repo: ZanshinRepository) -> ZanshinRepository:
        """Persist a repository, refusing URLs git would treat as anything
        other than a fetch (see `validate_repo_url`). Validation lives here
        rather than only in `ScanProcessor` so the operator finds out when
        adding the repository, not when the first scan fails."""
        repo.url = validate_repo_url(repo.url)
        return self.repository_repository.save(repo)

    def delete_by_id(self, repo_id: int):
        return self.repository_repository.delete_by_id(repo_id)

    def trigger_scan(self, repo_id: int) -> Scan:
        repo = self.repository_repository.find_by_id(repo_id)
        if not repo:
            raise RuntimeError("Repository not found")

        # One scan in flight per target. Without this, a key holder (or a stuck
        # scheduler) can queue scans without limit: the pool has five workers, so
        # the rest pile up as rows, each eventually writing a multi-megabyte SBOM.
        # A second scan of the same target while the first runs also can't tell you
        # anything the first won't.
        in_flight = self.scan_repository.find_in_flight_for_repository(repo_id)
        if in_flight:
            raise ScanAlreadyRunningError(
                f"Un scan est déjà en cours pour ce dépôt (scan {in_flight.id})."
            )

        scan = Scan(
            repo_id=repo.id,
            branch=repo.branch if repo.branch else "main",
            sub_path=repo.sub_path if repo.sub_path else "",
            status="pending",
            findings_count=0,
            created_at=utcnow()
        )
        scan = self.scan_repository.save(scan)

        # Queued, not submitted. The row *is* the queue entry, so it survives a restart
        # and its place in line is answerable; `dispatch` starts it immediately when
        # there is capacity, and leaves it waiting in order when there is not.
        #
        # The returned status is therefore `pending` *or* `scanning` depending on
        # whether a slot was free — which is the honest answer, and why the API replies
        # 202 and expects the caller to poll.
        dispatch()
        self.scan_repository.db.refresh(scan)
        return scan

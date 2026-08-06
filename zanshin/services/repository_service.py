import concurrent.futures
import os
from typing import List
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan
from zanshin.repositories.repository_repository import RepositoryRepository
from zanshin.repositories.scan_repository import ScanRepository
from zanshin.services.scan_processor import ScanProcessor
from zanshin.clock import utcnow
from zanshin.services.git_url import validate_repo_url


class ScanAlreadyRunningError(RuntimeError):
    """A scan of this target is already pending or running.

    A `RuntimeError` subclass so the existing UI and API error handling reports it
    unchanged, and distinguishable for the API, which answers 409 rather than 404.
    """

# Scans are blocking (git clone, then containers or subprocesses), so they run
# on this shared pool rather than on the event loop thread — a scan must never
# freeze the UI for everyone. Shared with `ContainerService` on purpose: the
# limit is about how many scanners the host can run at once, not about which
# kind of target they belong to.
#
# Sized from the environment because the right number depends on the machine:
# every worker can hold a Docker container (or a sidecar request) open at once.
SCAN_WORKERS = int(os.getenv("ZANSHIN_SCAN_WORKERS", "5"))
executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=SCAN_WORKERS, thread_name_prefix="zanshin-scan"
)

class RepositoryService:
    def __init__(self, repository_repository: RepositoryRepository, scan_repository: ScanRepository, scan_processor: ScanProcessor):
        self.repository_repository = repository_repository
        self.scan_repository = scan_repository
        self.scan_processor = scan_processor

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

        # Submitted straight to the pool, not via `asyncio.get_event_loop()` +
        # `run_in_executor`: that call is deprecated (and already emits "There is
        # no current event loop"), and it only ever existed to reach this same
        # executor. Nothing awaits the result, so an event loop was never needed
        # — `process_scan` reports progress through the database.
        executor.submit(
            self.scan_processor.process_scan,
            scan.id,
            repo.url,
            scan.branch,
            scan.sub_path,
            repo.ssh_key_id,
        )
        return scan

import asyncio
import concurrent.futures
from datetime import datetime
from typing import List
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan
from zanshin.repositories.repository_repository import RepositoryRepository
from zanshin.repositories.scan_repository import ScanRepository
from zanshin.services.scan_processor import ScanProcessor

# Thread executor to run blocking docker/git scans asynchronously
executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

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
        return self.repository_repository.save(repo)

    def delete_by_id(self, repo_id: int):
        return self.repository_repository.delete_by_id(repo_id)

    def trigger_scan(self, repo_id: int) -> Scan:
        repo = self.repository_repository.find_by_id(repo_id)
        if not repo:
            raise RuntimeError("Repository not found")

        scan = Scan(
            repo_id=repo.id,
            branch=repo.branch if repo.branch else "main",
            sub_path=repo.sub_path if repo.sub_path else "",
            status="pending",
            findings_count=0,
            created_at=datetime.utcnow()
        )
        scan = self.scan_repository.save(scan)

        # Run process_scan in background thread pool to prevent blocking the UI
        loop = asyncio.get_event_loop()
        loop.run_in_executor(
            executor,
            self.scan_processor.process_scan,
            scan.id,
            repo.url,
            scan.branch,
            scan.sub_path,
            repo.ssh_key_id
        )
        return scan

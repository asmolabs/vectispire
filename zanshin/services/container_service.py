from typing import List
from zanshin.models.container import Container
from zanshin.models.scan import Scan
from zanshin.repositories.container_repository import ContainerRepository
from zanshin.repositories.scan_repository import ScanRepository
from zanshin.services.scan_processor import ScanProcessor
from zanshin.clock import utcnow
from zanshin.services.repository_service import executor

class ContainerService:
    def __init__(self, container_repository: ContainerRepository, scan_repository: ScanRepository, scan_processor: ScanProcessor):
        self.container_repository = container_repository
        self.scan_repository = scan_repository
        self.scan_processor = scan_processor

    def find_all(self) -> List[Container]:
        return self.container_repository.find_all()

    def find_by_id(self, container_id: int) -> Container:
        return self.container_repository.find_by_id(container_id)

    def save(self, container: Container) -> Container:
        return self.container_repository.save(container)

    def delete_by_id(self, container_id: int):
        return self.container_repository.delete_by_id(container_id)

    def trigger_scan(self, container_id: int) -> Scan:
        container = self.container_repository.find_by_id(container_id)
        if not container:
            raise RuntimeError("Container not found")

        scan = Scan(
            container_id=container.id,
            branch=container.tag if container.tag else "latest",
            sub_path="",
            status="pending",
            findings_count=0,
            created_at=utcnow()
        )
        scan = self.scan_repository.save(scan)

        # Straight to the shared pool — see the note in RepositoryService about
        # why the deprecated `get_event_loop()` detour is gone.
        executor.submit(
            self.scan_processor.process_scan,
            scan.id,
            None,
            scan.branch,
            "",
            None,
        )
        return scan

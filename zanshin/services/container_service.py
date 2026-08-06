from typing import List
from zanshin.models.container import Container
from zanshin.models.scan import Scan
from zanshin.repositories.container_repository import ContainerRepository
from zanshin.repositories.scan_repository import ScanRepository
from zanshin.clock import utcnow
from zanshin.services.repository_service import ScanAlreadyRunningError
from zanshin.services.scan_queue import dispatch

class ContainerService:
    def __init__(self, container_repository: ContainerRepository, scan_repository: ScanRepository):
        """See `RepositoryService.__init__`: this queues a scan, it does not run one."""
        self.container_repository = container_repository
        self.scan_repository = scan_repository

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

        # See RepositoryService.trigger_scan: one scan in flight per target.
        in_flight = self.scan_repository.find_in_flight_for_container(container_id)
        if in_flight:
            raise ScanAlreadyRunningError(
                f"Un scan est déjà en cours pour cette image (scan {in_flight.id})."
            )

        scan = Scan(
            container_id=container.id,
            branch=container.tag if container.tag else "latest",
            sub_path="",
            status="pending",
            findings_count=0,
            created_at=utcnow()
        )
        scan = self.scan_repository.save(scan)

        # Queued in creation order like a repository scan — the limit is about how many
        # scanners the host runs at once, not about which kind of target they belong to.
        dispatch()
        self.scan_repository.db.refresh(scan)
        return scan

from sqlalchemy.orm import Session
from zanshin.database import SessionLocal

# Repositories
from zanshin.repositories.user_repository import UserRepository
from zanshin.repositories.repository_repository import RepositoryRepository
from zanshin.repositories.container_repository import ContainerRepository
from zanshin.repositories.scan_repository import ScanRepository
from zanshin.repositories.ssh_key_repository import SSHKeyRepository
from zanshin.repositories.api_key_repository import ApiKeyRepository
from zanshin.repositories.setting_repository import SettingRepository
from zanshin.repositories.vex_decision_repository import VexDecisionRepository

# Services
from zanshin.services.auth_service import AuthService
from zanshin.services.encryption_service import EncryptionService
from zanshin.services.ssh_key_service import SSHKeyService
from zanshin.services.scan_processor import ScanProcessor
from zanshin.services.repository_service import RepositoryService
from zanshin.services.container_service import ContainerService
from zanshin.services.settings_service import SettingsService

class IoCContainer:
    def __init__(self, db: Session):
        self.db = db
        
        # Repositories
        self.user_repository = UserRepository(db)
        self.repository_repository = RepositoryRepository(db)
        self.container_repository = ContainerRepository(db)
        self.scan_repository = ScanRepository(db)
        self.ssh_key_repository = SSHKeyRepository(db)
        self.api_key_repository = ApiKeyRepository(db)
        self.setting_repository = SettingRepository(db)
        self.vex_decision_repository = VexDecisionRepository(db)
        
        # Services
        self.encryption_service = EncryptionService()
        self.auth_service = AuthService(self.user_repository)
        self.ssh_key_service = SSHKeyService(self.ssh_key_repository, self.encryption_service)
        self.scan_processor = ScanProcessor(self.ssh_key_service)
        self.repository_service = RepositoryService(
            self.repository_repository, 
            self.scan_repository, 
            self.scan_processor
        )
        self.container_service = ContainerService(
            self.container_repository, 
            self.scan_repository, 
            self.scan_processor
        )
        self.settings_service = SettingsService(self.setting_repository)

def get_container() -> IoCContainer:
    """Return a container instance wrapping a new database session."""
    db = SessionLocal()
    return IoCContainer(db)

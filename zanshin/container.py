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
from zanshin.repositories.finding_repository import FindingRepository
from zanshin.repositories.audit_log_repository import AuditLogRepository

# Services
from zanshin.services.auth_service import AuthService
from zanshin.services.encryption_service import EncryptionService
from zanshin.services.ssh_key_service import SSHKeyService
from zanshin.services.scan_processor import ScanProcessor
from zanshin.services.repository_service import RepositoryService
from zanshin.services.container_service import ContainerService
from zanshin.services.settings_service import SettingsService
from zanshin.services.api_key_service import ApiKeyService
from zanshin.services.scanners import get_scanner_engine
from zanshin.services.enrichment_service import EnrichmentService
from zanshin.services.license_compliance_service import LicenseComplianceService
from zanshin.services.user_service import UserService
from zanshin.services.audit_log_service import AuditLogService
from zanshin.services.ai_review_service import AiReviewService

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
        self.finding_repository = FindingRepository(db)
        self.audit_log_repository = AuditLogRepository(db)

        # Services
        self.encryption_service = EncryptionService()
        self.auth_service = AuthService(self.user_repository)
        self.user_service = UserService(self.user_repository, self.auth_service)
        self.audit_log_service = AuditLogService(self.audit_log_repository)
        self.ssh_key_service = SSHKeyService(self.ssh_key_repository, self.encryption_service)
        self.settings_service = SettingsService(self.setting_repository)
        self.api_key_service = ApiKeyService(self.api_key_repository)

        # `scan_backend` setting picks the ScannerEngine implementation
        # (only "docker" exists today — see ADR-001 for the local-API/
        # cloud-API backends planned as pluggable alternatives).
        self.scanner_engine = get_scanner_engine(self.settings_service)
        # EPSS/CISA-KEV scoring after a scan completes; disable via the
        # `enrichment_enabled` setting for fully air-gapped deployments.
        self.enrichment_service = EnrichmentService(self.settings_service)
        # License blocklist evaluation over the SBOM (no scanner needed —
        # see LicenseComplianceService's docstring / ADR-001 section 5).
        self.license_compliance_service = LicenseComplianceService(self.settings_service)
        # Optional local LLM-based code review via Ollama (disabled by
        # default). Config-only for now: not called from ScanProcessor yet
        # — see AiReviewService's docstring.
        self.ai_review_service = AiReviewService(self.settings_service)
        self.scan_processor = ScanProcessor(
            self.ssh_key_service,
            self.scanner_engine,
            self.enrichment_service,
            self.license_compliance_service
        )
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

def get_container() -> IoCContainer:
    """Return a container instance wrapping a new database session."""
    db = SessionLocal()
    return IoCContainer(db)

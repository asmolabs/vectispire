"""Manual dependency injection.

Built lazily, one `cached_property` per dependency. The previous version
constructed all twenty-six objects in `__init__`, and since a container is
created per UI event and per API request, *every* interaction paid for the whole
graph — including `get_scanner_engine()`, which reads the `scan_backend` setting
from the database. Clicking a filter on the issues screen did a scan-backend
lookup it had no use for, and a malformed `scan_backend` value made every screen
fail rather than just scanning (the concrete failure that the bootstrap had to
work around by wiring its three objects by hand).

`cached_property` keeps the access syntax identical (`container.user_service`),
builds each object at most once per container, and builds nothing that isn't
asked for.
"""
from functools import cached_property

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
from zanshin.repositories.finding_repository import FindingRepository
from zanshin.repositories.audit_log_repository import AuditLogRepository
from zanshin.repositories.ai_review_result_repository import AiReviewResultRepository
from zanshin.repositories.issue_repository import IssueRepository
from zanshin.repositories.gate_policy_repository import GatePolicyRepository
from zanshin.repositories.outbox_repository import OutboxRepository
from zanshin.repositories.agent_repository import AgentRepository
from zanshin.repositories.processed_message_repository import ProcessedMessageRepository

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
from zanshin.services.eol_service import EolService
from zanshin.services.gate_policy_service import GatePolicyService
from zanshin.services.ticket_service import TicketService
from zanshin.services.license_compliance_service import LicenseComplianceService
from zanshin.services.retention_service import RetentionService
from zanshin.services.user_service import UserService
from zanshin.services.audit_log_service import AuditLogService
from zanshin.services.ai_review_service import AiReviewService
from zanshin.services.issue_service import IssueService
from zanshin.services.notification_service import NotificationService
from zanshin.services.agent_service import AgentService
from zanshin.services.agent_job_service import AgentJobService
from zanshin.services.sast_service import SastService
from zanshin.services.scan_ingestor import ScanIngestor


class IoCContainer:
    def __init__(self, db: Session):
        self.db = db

    # --- Repositories ---

    @cached_property
    def user_repository(self) -> UserRepository:
        return UserRepository(self.db)

    @cached_property
    def repository_repository(self) -> RepositoryRepository:
        return RepositoryRepository(self.db)

    @cached_property
    def container_repository(self) -> ContainerRepository:
        return ContainerRepository(self.db)

    @cached_property
    def scan_repository(self) -> ScanRepository:
        return ScanRepository(self.db)

    @cached_property
    def ssh_key_repository(self) -> SSHKeyRepository:
        return SSHKeyRepository(self.db)

    @cached_property
    def api_key_repository(self) -> ApiKeyRepository:
        return ApiKeyRepository(self.db)

    @cached_property
    def setting_repository(self) -> SettingRepository:
        return SettingRepository(self.db)

    @cached_property
    def finding_repository(self) -> FindingRepository:
        return FindingRepository(self.db)

    @cached_property
    def audit_log_repository(self) -> AuditLogRepository:
        return AuditLogRepository(self.db)

    @cached_property
    def ai_review_result_repository(self) -> AiReviewResultRepository:
        return AiReviewResultRepository(self.db)

    @cached_property
    def issue_repository(self) -> IssueRepository:
        return IssueRepository(self.db)

    @cached_property
    def gate_policy_repository(self) -> GatePolicyRepository:
        return GatePolicyRepository(self.db)

    @cached_property
    def outbox_repository(self) -> OutboxRepository:
        return OutboxRepository(self.db)

    @cached_property
    def agent_repository(self) -> AgentRepository:
        return AgentRepository(self.db)

    @cached_property
    def processed_message_repository(self) -> ProcessedMessageRepository:
        return ProcessedMessageRepository(self.db)

    # --- Services ---

    @cached_property
    def encryption_service(self) -> EncryptionService:
        return EncryptionService()

    @cached_property
    def auth_service(self) -> AuthService:
        return AuthService(self.user_repository)

    @cached_property
    def user_service(self) -> UserService:
        return UserService(self.user_repository, self.auth_service)

    @cached_property
    def audit_log_service(self) -> AuditLogService:
        return AuditLogService(self.audit_log_repository)

    @cached_property
    def ssh_key_service(self) -> SSHKeyService:
        return SSHKeyService(self.ssh_key_repository, self.encryption_service)

    @cached_property
    def settings_service(self) -> SettingsService:
        return SettingsService(self.setting_repository)

    @cached_property
    def api_key_service(self) -> ApiKeyService:
        return ApiKeyService(self.api_key_repository)

    @cached_property
    def scanner_engine(self):
        """The `scan_backend` setting picks the implementation (docker /
        local_api / osv — see docs/architecture/). Reads the database, which is why it
        matters that nothing builds it unless a scan is actually involved."""
        return get_scanner_engine(self.settings_service)

    @cached_property
    def enrichment_service(self) -> EnrichmentService:
        """EPSS/CISA-KEV scoring after a scan completes; disable via the
        `enrichment_enabled` setting for fully air-gapped deployments."""
        return EnrichmentService(self.settings_service)

    @cached_property
    def license_compliance_service(self) -> LicenseComplianceService:
        """License blocklist evaluation over the SBOM (no scanner needed — see
        its docstring / docs/architecture/01)."""
        return LicenseComplianceService(self.settings_service)

    @cached_property
    def eol_service(self) -> EolService:
        """End-of-life detection for the platforms a target ships, from
        endoflife.date; disable via the `eol_detection_enabled` setting."""
        return EolService(self.settings_service)

    @cached_property
    def sast_service(self) -> SastService:
        """Semgrep source-code analysis, disabled by default (`sast_enabled`). Owns both
        the toggle and the translation of Semgrep's output into `sast` (security) and
        `quality` findings."""
        return SastService(self.settings_service)

    @cached_property
    def ai_review_service(self) -> AiReviewService:
        """Optional local LLM code review via Ollama, disabled by default (see
        docs/architecture/01)."""
        return AiReviewService(self.settings_service)

    @cached_property
    def issue_service(self) -> IssueService:
        """Cross-scan issue lifecycle and triage. Session-agnostic by design —
        `sync_from_scan` runs on the background scan session, `triage` on this
        request's session."""
        return IssueService()

    @cached_property
    def notification_service(self) -> NotificationService:
        """Outbound webhook about what a scan changed; inert until a URL is set
        in Settings."""
        return NotificationService(self.settings_service)

    @cached_property
    def gate_policy_service(self) -> GatePolicyService:
        """Resolves which gate policy applies to a target, and versions changes to
        it. The policy used to arrive in the request body — see its docstring."""
        return GatePolicyService(self.gate_policy_repository)

    @cached_property
    def ticket_service(self) -> TicketService:
        """Opens tracker tickets for what would fail a build; inert until a
        provider, project and token are configured."""
        return TicketService(self.settings_service, self.encryption_service)

    @cached_property
    def retention_service(self) -> RetentionService:
        """Prunes the raw scanner payloads that make the database grow without
        bound (see its docstring)."""
        return RetentionService(self.settings_service)

    @cached_property
    def scan_processor(self) -> ScanProcessor:
        return ScanProcessor(
            self.ssh_key_service,
            self.scanner_engine,
            self.enrichment_service,
            self.license_compliance_service,
            self.ai_review_service,
            self.issue_service,
            self.notification_service,
            eol_service=self.eol_service,
            sast_service=self.sast_service,
        )

    @cached_property
    def agent_service(self) -> AgentService:
        """The registry of workers allowed to run scans — including this process
        itself, which is a row like any other (see AgentService)."""
        return AgentService(
            self.agent_repository,
            api_key_service=self.api_key_service,
            settings_service=self.settings_service,
        )

    @cached_property
    def scan_ingestor(self) -> ScanIngestor:
        """The ingestion half of the pipeline, on its own.

        `scan_processor` composes the same object with a `ScanRunner`; this property
        exists because a result arriving from a remote agent needs ingestion and
        nothing else — building the processor would also build the scanner engine,
        so a malformed `scan_backend` setting would block results from machines
        that scanned perfectly well.
        """
        return ScanIngestor(
            enrichment_service=self.enrichment_service,
            license_compliance_service=self.license_compliance_service,
            ai_review_service=self.ai_review_service,
            issue_service=self.issue_service,
            notification_service=self.notification_service,
            eol_service=self.eol_service,
            sast_service=self.sast_service,
        )

    @cached_property
    def agent_job_service(self) -> AgentJobService:
        """Hands work to remote agents and takes their results back."""
        return AgentJobService(
            agent_service=self.agent_service,
            scan_repository=self.scan_repository,
            ssh_key_service=self.ssh_key_service,
            scan_ingestor=self.scan_ingestor,
            processed_message_repository=self.processed_message_repository,
            audit_log_service=self.audit_log_service,
        )

    @cached_property
    def repository_service(self) -> RepositoryService:
        return RepositoryService(self.repository_repository, self.scan_repository)

    @cached_property
    def container_service(self) -> ContainerService:
        return ContainerService(self.container_repository, self.scan_repository)


def get_container() -> IoCContainer:
    """Return a container instance wrapping a new database session."""
    db = SessionLocal()
    return IoCContainer(db)

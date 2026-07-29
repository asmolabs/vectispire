"""Smoke tests for IoCContainer wiring.

Not exhaustive behavioral tests (each service already has its own test
module) — the point here is to catch wiring mistakes: a constructor
argument in the wrong order, a repository bound to the wrong service, a
forgotten import. Uses the same in-memory-SQLite discipline as the rest of
the suite (see conftest.py) — never touches the real database file.
"""
from zanshin.container import IoCContainer
from zanshin.services.scanners.docker_engine import DockerScannerEngine
from zanshin.services.enrichment_service import EnrichmentService
from zanshin.services.license_compliance_service import LicenseComplianceService
from zanshin.services.scan_processor import ScanProcessor
from zanshin.services.user_service import UserService
from zanshin.services.audit_log_service import AuditLogService
from zanshin.services.ai_review_service import AiReviewService


def test_container_wires_every_repository_and_service_without_error(db_session):
    container = IoCContainer(db_session)

    # Repositories
    assert container.user_repository.db is db_session
    assert container.finding_repository.db is db_session
    assert container.audit_log_repository.db is db_session

    # Services default to their expected concrete implementations.
    assert isinstance(container.scanner_engine, DockerScannerEngine)
    assert isinstance(container.enrichment_service, EnrichmentService)
    assert isinstance(container.license_compliance_service, LicenseComplianceService)
    assert isinstance(container.scan_processor, ScanProcessor)
    assert isinstance(container.user_service, UserService)
    assert isinstance(container.audit_log_service, AuditLogService)
    assert isinstance(container.ai_review_service, AiReviewService)

    # ScanProcessor and the repo/container services must share the SAME
    # scanner_engine/enrichment_service/license_compliance_service instances
    # the container built, not fresh copies.
    assert container.scan_processor.scanner_engine is container.scanner_engine
    assert container.scan_processor.enrichment_service is container.enrichment_service
    assert container.scan_processor.license_compliance_service is container.license_compliance_service
    assert container.repository_service.scan_processor is container.scan_processor
    assert container.container_service.scan_processor is container.scan_processor

    # UserService/AuditLogService depend on the SAME repositories, not new ones.
    assert container.user_service.user_repository is container.user_repository
    assert container.audit_log_service.audit_log_repository is container.audit_log_repository


def test_get_container_uses_a_real_session_factory(isolated_session_local):
    """`get_container()` opens its own `SessionLocal()` — it is only used
    by the Reflex UI layer at request time. We redirect that factory to an
    isolated in-memory session (never the real `zanshin/database.sqlite`,
    per this suite's testing discipline — see conftest.py) and just check
    the wiring completes and the factory was actually invoked."""
    from zanshin import container as container_module

    calls = []

    def counting_session_local():
        calls.append("session-created")
        return isolated_session_local()

    original = container_module.SessionLocal
    try:
        container_module.SessionLocal = counting_session_local
        result = container_module.get_container()
        assert isinstance(result, IoCContainer)
        assert calls == ["session-created"]
    finally:
        container_module.SessionLocal = original

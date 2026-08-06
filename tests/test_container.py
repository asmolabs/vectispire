"""Tests for the IoC container.

A container is built per UI event and per API request, so what it costs to
construct is paid on every interaction. It used to build all twenty-six
dependencies eagerly — including the scanner engine, which reads a setting from
the database.
"""
import pytest

import zanshin.container as container_module
from zanshin.container import IoCContainer
from zanshin.models.setting import Setting
from zanshin.services.ai_review_service import AiReviewService
from zanshin.services.audit_log_service import AuditLogService
from zanshin.services.enrichment_service import EnrichmentService
from zanshin.services.license_compliance_service import LicenseComplianceService
from zanshin.services.scan_processor import ScanProcessor
from zanshin.services.scanners.docker_engine import DockerScannerEngine
from zanshin.services.user_service import UserService


def test_nothing_is_built_until_it_is_asked_for(db_session, monkeypatch):
    """The concrete waste: clicking a filter on the issues screen used to do a
    `scan_backend` lookup it had no use for."""
    calls = []
    monkeypatch.setattr(
        container_module, "get_scanner_engine", lambda settings: calls.append(1) or object()
    )

    container = IoCContainer(db_session)
    container.issue_repository
    container.user_service

    assert calls == []  # no scanner engine, so no settings read

    container.scanner_engine
    assert calls == [1]


def test_an_invalid_scan_backend_only_breaks_scanning(db_session):
    """Previously it broke *every* screen, because every container built the
    engine. That is why the startup bootstrap had to wire its three objects by
    hand instead of using the container."""
    db_session.add(Setting(key="scan_backend", value="does-not-exist"))
    db_session.commit()
    container = IoCContainer(db_session)

    # Unrelated dependencies still work...
    assert container.user_repository is not None
    assert container.issue_repository is not None
    assert container.audit_log_service is not None

    # ...and the failure surfaces only where it belongs.
    with pytest.raises(ValueError, match="Backend de scan"):
        container.scanner_engine


def test_each_dependency_is_built_once(db_session):
    container = IoCContainer(db_session)

    assert container.user_repository is container.user_repository
    assert container.settings_service is container.settings_service
    # ...and shared, not duplicated, between the services that need it.
    assert container.user_service.user_repository is container.user_repository
    assert container.auth_service.user_repository is container.user_repository


def test_every_dependency_shares_the_request_session(db_session):
    container = IoCContainer(db_session)

    for name in (
        "user_repository", "repository_repository", "container_repository",
        "scan_repository", "ssh_key_repository", "api_key_repository",
        "setting_repository", "finding_repository", "audit_log_repository",
        "ai_review_result_repository", "issue_repository",
    ):
        assert getattr(container, name).db is db_session, name


def test_the_whole_graph_is_still_constructible(db_session):
    """Lazy must not mean unreachable: the scan pipeline needs almost all of it."""
    container = IoCContainer(db_session)

    assert container.scan_processor is not None
    assert container.scan_processor.issue_service is container.issue_service
    # The scan services deliberately do *not* hold a processor: they queue a scan, and
    # the dispatcher resolves a processor from a container when it claims the row —
    # which is what lets a scan queued before a restart still be run.
    assert not hasattr(container.repository_service, "scan_processor")
    assert not hasattr(container.container_service, "scan_processor")
    assert container.scan_processor.notification_service is container.notification_service
    assert container.retention_service is not None


def test_services_resolve_to_their_expected_implementations(db_session):
    """Wiring smoke test: a constructor argument in the wrong order or a
    repository bound to the wrong service shows up here, not in production."""
    container = IoCContainer(db_session)

    assert isinstance(container.scanner_engine, DockerScannerEngine)
    assert isinstance(container.enrichment_service, EnrichmentService)
    assert isinstance(container.license_compliance_service, LicenseComplianceService)
    assert isinstance(container.scan_processor, ScanProcessor)
    assert isinstance(container.user_service, UserService)
    assert isinstance(container.audit_log_service, AuditLogService)
    assert isinstance(container.ai_review_service, AiReviewService)


def test_the_pipeline_reuses_the_containers_instances(db_session):
    """`ScanProcessor` must receive the objects the container built, not fresh
    copies — otherwise a setting read once is read again, and mocks in tests
    don't apply."""
    container = IoCContainer(db_session)

    assert container.scan_processor.scanner_engine is container.scanner_engine
    assert container.scan_processor.enrichment_service is container.enrichment_service
    assert (
        container.scan_processor.license_compliance_service
        is container.license_compliance_service
    )
    assert container.scan_processor.ai_review_service is container.ai_review_service
    assert container.audit_log_service.audit_log_repository is container.audit_log_repository


def test_get_container_uses_the_module_session_factory(isolated_session_local, monkeypatch):
    """`get_container()` opens its own session; it is what the UI layer calls per
    event. Redirected here to an isolated in-memory database, never the real
    file (see conftest.py)."""
    calls = []

    def counting_session_local():
        calls.append("session-created")
        return isolated_session_local()

    monkeypatch.setattr(container_module, "SessionLocal", counting_session_local)

    result = container_module.get_container()

    assert isinstance(result, IoCContainer)
    assert calls == ["session-created"]
    result.db.close()

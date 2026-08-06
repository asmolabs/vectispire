"""Tests for ContainerService — mirrors test_repository_service.py's
approach (real background executor, fake ScanProcessor, threading.Event to
synchronize)."""
import threading

import pytest

from zanshin.services.container_service import ContainerService


@pytest.fixture()
def service(container_repository, scan_repository, scan_dispatch):
    svc = ContainerService(container_repository, scan_repository)
    return svc, scan_dispatch


def test_find_all_find_by_id_save_delete_delegate_to_repository(container_repository, make_container, service):
    svc, _ = service
    c = make_container(image_name="nginx")

    assert svc.find_by_id(c.id).id == c.id
    assert any(x.id == c.id for x in svc.find_all())

    c.tag = "1.25"
    svc.save(c)
    assert container_repository.find_by_id(c.id).tag == "1.25"

    svc.delete_by_id(c.id)
    assert container_repository.find_by_id(c.id) is None


def test_trigger_scan_raises_when_container_not_found(service):
    svc, _ = service
    with pytest.raises(RuntimeError):
        svc.trigger_scan(9999)


def test_trigger_scan_creates_pending_scan_with_no_repo_url_or_ssh_key(make_container, scan_repository, service):
    svc, fake_processor = service
    container = make_container(image_name="nginx", tag="1.27", registry="ghcr.io")

    scan = svc.trigger_scan(container.id)

    assert scan.container_id == container.id
    assert scan.branch == "1.27"
    assert scan.sub_path == ""
    assert scan.status in ("pending", "scanning")
    assert scan_repository.find_by_id(scan.id) is not None

    assert fake_processor.done.wait(timeout=2), "process_scan was never dispatched to the background executor"
    # Container scans never pass a repo_url or ssh_key_id — there's no git
    # clone step for an image-based scan.
    assert fake_processor.calls == [(scan.id, None, "1.27", "", None)]

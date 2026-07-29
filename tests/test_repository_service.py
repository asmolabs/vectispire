"""Tests for RepositoryService.

`trigger_scan` schedules `ScanProcessor.process_scan` on the module-level
background `ThreadPoolExecutor` (`repository_service.executor`, shared with
`ContainerService`) rather than calling it inline — that's real production
behavior we want covered, so these tests let it actually run against a
fake `ScanProcessor` (never against real Docker/git) and use a
`threading.Event` to wait for the background thread to finish before
asserting on it.
"""
import threading

import pytest

from zanshin.models.repository import ZanshinRepository
from zanshin.services.repository_service import RepositoryService


class FakeScanProcessor:
    def __init__(self):
        self.calls = []
        self.done = threading.Event()

    def process_scan(self, scan_id, repo_url, branch, sub_path, ssh_key_id):
        self.calls.append((scan_id, repo_url, branch, sub_path, ssh_key_id))
        self.done.set()


@pytest.fixture()
def service(repository_repository, scan_repository):
    fake_processor = FakeScanProcessor()
    svc = RepositoryService(repository_repository, scan_repository, fake_processor)
    return svc, fake_processor


def test_find_all_find_by_id_save_delete_delegate_to_repository(repository_repository, make_repository, service):
    svc, _ = service
    repo = make_repository(url="git@example.com:org/a.git")

    assert svc.find_by_id(repo.id).id == repo.id
    assert any(r.id == repo.id for r in svc.find_all())

    repo.name = "renamed"
    svc.save(repo)
    assert repository_repository.find_by_id(repo.id).name == "renamed"

    svc.delete_by_id(repo.id)
    assert repository_repository.find_by_id(repo.id) is None


def test_trigger_scan_raises_when_repository_not_found(service):
    svc, _ = service
    with pytest.raises(RuntimeError):
        svc.trigger_scan(9999)


def test_trigger_scan_creates_pending_scan_and_dispatches_to_scan_processor(make_repository, scan_repository, service):
    svc, fake_processor = service
    repo = make_repository(url="git@example.com:org/a.git", branch="develop", sub_path="services/api")

    scan = svc.trigger_scan(repo.id)

    assert scan.id is not None
    assert scan.repo_id == repo.id
    assert scan.branch == "develop"
    assert scan.sub_path == "services/api"
    assert scan.status == "pending"
    assert scan_repository.find_by_id(scan.id) is not None

    assert fake_processor.done.wait(timeout=2), "process_scan was never dispatched to the background executor"
    assert fake_processor.calls == [(scan.id, repo.url, "develop", "services/api", repo.ssh_key_id)]


def test_trigger_scan_defaults_sub_path_to_empty_string_when_null(repository_repository, service):
    # `branch` is a NOT NULL column with a server-side default, so a
    # persisted repository always has a real value — but `sub_path` is
    # nullable, so the `repo.sub_path if repo.sub_path else ""` fallback in
    # `trigger_scan` is reachable and worth covering.
    svc, fake_processor = service
    repo = ZanshinRepository(url="git@example.com:org/b.git", branch="main", sub_path=None)
    repo = repository_repository.save(repo)

    scan = svc.trigger_scan(repo.id)

    assert scan.sub_path == ""
    assert fake_processor.done.wait(timeout=2)

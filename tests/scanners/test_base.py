from zanshin.services.scanners.docker_engine import DockerScannerEngine
from zanshin.services.scanners.osv_engine import OsvScannerEngine


def test_get_workspace_root_defaults_to_none_for_docker_backend():
    assert DockerScannerEngine().get_workspace_root() is None


def test_get_workspace_root_defaults_to_none_for_osv_backend():
    assert OsvScannerEngine(local_engine=DockerScannerEngine()).get_workspace_root() is None

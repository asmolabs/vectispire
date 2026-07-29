import pytest

from zanshin.services.scanners.factory import (
    get_scanner_engine,
    SETTING_KEY_SCAN_BACKEND,
    SETTING_KEY_LOCAL_API_URL,
    SETTING_KEY_LOCAL_API_SHARED_DIR,
)
from zanshin.services.scanners.docker_engine import DockerScannerEngine
from zanshin.services.scanners.osv_engine import OsvScannerEngine
from zanshin.services.scanners.local_api_engine import LocalApiScannerEngine


def test_defaults_to_docker_backend(settings_service):
    engine = get_scanner_engine(settings_service)
    assert isinstance(engine, DockerScannerEngine)


def test_selects_osv_backend(settings_service):
    settings_service.update_setting(SETTING_KEY_SCAN_BACKEND, "osv")
    engine = get_scanner_engine(settings_service)
    assert isinstance(engine, OsvScannerEngine)


def test_selects_local_api_backend_with_configured_url_and_shared_dir(settings_service):
    settings_service.update_setting(SETTING_KEY_SCAN_BACKEND, "local_api")
    settings_service.update_setting(SETTING_KEY_LOCAL_API_URL, "http://scan-api:9000")
    settings_service.update_setting(SETTING_KEY_LOCAL_API_SHARED_DIR, "/shared/zanshin-scans")

    engine = get_scanner_engine(settings_service)

    assert isinstance(engine, LocalApiScannerEngine)
    assert engine.base_url == "http://scan-api:9000"
    assert engine.get_workspace_root() == "/shared/zanshin-scans"


def test_unknown_backend_raises_clear_error(settings_service):
    settings_service.update_setting(SETTING_KEY_SCAN_BACKEND, "bogus")

    with pytest.raises(ValueError):
        get_scanner_engine(settings_service)

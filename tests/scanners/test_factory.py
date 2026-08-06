import pytest

from zanshin.services.scanners.factory import (
    get_scanner_engine,
    SETTING_KEY_SCAN_BACKEND,
    SETTING_KEY_LOCAL_API_URL,
    SETTING_KEY_LOCAL_API_SHARED_DIR,
    SETTING_KEY_IMAGE_SCAN_PLATFORM,
)
from zanshin.services.scanners.docker_engine import (
    DEFAULT_IMAGE_SCAN_PLATFORM,
    DockerScannerEngine,
)
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


# --- image_scan_platform ----------------------------------------------------


def test_image_scan_platform_defaults_when_unset(settings_service):
    engine = get_scanner_engine(settings_service)
    assert engine.image_scan_platform == DEFAULT_IMAGE_SCAN_PLATFORM


def test_image_scan_platform_is_read_from_settings(settings_service):
    settings_service.update_setting(SETTING_KEY_IMAGE_SCAN_PLATFORM, "linux/arm64")

    engine = get_scanner_engine(settings_service)

    assert engine.image_scan_platform == "linux/arm64"


def test_osv_backend_also_honours_the_platform_setting(settings_service):
    """The osv backend delegates only vulnerability matching to the cloud —
    its SBOM is still built by a local DockerScannerEngine, which would
    otherwise silently audit the default platform."""
    settings_service.update_setting(SETTING_KEY_SCAN_BACKEND, "osv")
    settings_service.update_setting(SETTING_KEY_IMAGE_SCAN_PLATFORM, "linux/s390x")

    engine = get_scanner_engine(settings_service)

    assert engine._local_engine.image_scan_platform == "linux/s390x"


@pytest.mark.parametrize("stored", ["", "   "])
def test_blank_platform_setting_falls_back_to_the_default(settings_service, stored):
    """A blank row means "unset", not "no platform": an empty --platform
    would let the daemon pick the host architecture."""
    settings_service.update_setting(SETTING_KEY_IMAGE_SCAN_PLATFORM, stored)

    engine = get_scanner_engine(settings_service)

    assert engine.image_scan_platform == DEFAULT_IMAGE_SCAN_PLATFORM

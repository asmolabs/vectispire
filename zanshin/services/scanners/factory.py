from zanshin.services.scanners.base import ScannerEngine
from zanshin.services.scanners.docker_engine import (
    DEFAULT_IMAGE_SCAN_PLATFORM,
    DockerScannerEngine,
)
from zanshin.services.scanners.osv_engine import OsvScannerEngine
from zanshin.services.scanners.local_api_engine import LocalApiScannerEngine
from zanshin.services.settings_service import SettingsService

# Stored in the generic `setting` key/value table (see SettingsService).
SETTING_KEY_SCAN_BACKEND = "scan_backend"
SETTING_KEY_LOCAL_API_URL = "local_scan_api_url"
SETTING_KEY_LOCAL_API_SHARED_DIR = "local_scan_api_shared_dir"
SETTING_KEY_IMAGE_SCAN_PLATFORM = "image_scan_platform"
SETTING_KEY_LOCAL_API_TOKEN = "local_scan_api_token"

DEFAULT_LOCAL_API_URL = "http://localhost:8686"

def get_scanner_engine(settings_service: SettingsService) -> ScannerEngine:
    """Select the scan execution backend from the `scan_backend` setting.

    - "docker" (default): everything (SBOM, vulnerability matching, secrets,
      IaC) runs in ephemeral local containers — nothing leaves the host.
    - "local_api": every step is delegated over HTTP to a sidecar service
      (`scan-api/`) sharing a volume with Zanshin — see
      LocalApiScannerEngine's docstring and ADR-001 Phase 4. Configured via
      `local_scan_api_url` and `local_scan_api_shared_dir`.
    - "osv": vulnerability matching is delegated to the free OSV.dev cloud
      API instead of running Grype locally; SBOM generation and secrets
      scanning still run locally (see OsvScannerEngine's docstring for why).

    `image_scan_platform` configures which architecture container images are
    audited as. It applies to "osv" too: that backend only delegates
    vulnerability *matching* to the cloud, and still builds its SBOM with a
    local DockerScannerEngine — so it has to be built with the same
    platform rather than left on the default.
    """
    backend = settings_service.get_setting(SETTING_KEY_SCAN_BACKEND, "docker")
    image_scan_platform = settings_service.get_setting(
        SETTING_KEY_IMAGE_SCAN_PLATFORM, DEFAULT_IMAGE_SCAN_PLATFORM
    )
    if backend == "docker":
        return DockerScannerEngine(image_scan_platform=image_scan_platform)
    if backend == "osv":
        return OsvScannerEngine(
            local_engine=DockerScannerEngine(image_scan_platform=image_scan_platform)
        )
    if backend == "local_api":
        return LocalApiScannerEngine(
            base_url=settings_service.get_setting(SETTING_KEY_LOCAL_API_URL, DEFAULT_LOCAL_API_URL),
            shared_workspace_root=settings_service.get_setting(SETTING_KEY_LOCAL_API_SHARED_DIR, ""),
            image_scan_platform=image_scan_platform,
            auth_token=settings_service.get_setting(SETTING_KEY_LOCAL_API_TOKEN, ""),
        )
    raise ValueError(
        f"Backend de scan inconnu ou pas encore implémenté : '{backend}'. "
        "Backends disponibles : 'docker', 'local_api', 'osv' (voir ADR-001)."
    )

from zanshin.services.scanners.base import ScannerEngine
from zanshin.services.scanners.docker_engine import DockerScannerEngine
from zanshin.services.scanners.osv_engine import OsvScannerEngine
from zanshin.services.scanners.local_api_engine import LocalApiScannerEngine
from zanshin.services.settings_service import SettingsService

# Stored in the generic `setting` key/value table (see SettingsService).
SETTING_KEY_SCAN_BACKEND = "scan_backend"
SETTING_KEY_LOCAL_API_URL = "local_scan_api_url"
SETTING_KEY_LOCAL_API_SHARED_DIR = "local_scan_api_shared_dir"

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
    """
    backend = settings_service.get_setting(SETTING_KEY_SCAN_BACKEND, "docker")
    if backend == "docker":
        return DockerScannerEngine()
    if backend == "osv":
        return OsvScannerEngine()
    if backend == "local_api":
        return LocalApiScannerEngine(
            base_url=settings_service.get_setting(SETTING_KEY_LOCAL_API_URL, DEFAULT_LOCAL_API_URL),
            shared_workspace_root=settings_service.get_setting(SETTING_KEY_LOCAL_API_SHARED_DIR, ""),
        )
    raise ValueError(
        f"Backend de scan inconnu ou pas encore implémenté : '{backend}'. "
        "Backends disponibles : 'docker', 'local_api', 'osv' (voir ADR-001)."
    )

import os
from typing import Any, Dict, Optional

import httpx

from zanshin.services.scanners.base import ScannerEngine

# Scans can take a while (image pulls, large repos) — the sidecar service
# has no reason to be faster than the Docker backend's own container
# startup + tool run time, so this stays generous.
DEFAULT_TIMEOUT_SECONDS = 180.0

class LocalApiScannerEngine(ScannerEngine):
    """Delegates every step to a sidecar HTTP service (`scan-api/`, see
    ADR-001 Phase 4 and `scan-api/README.md`) instead of spinning up a
    Docker container per step from inside Zanshin's own process.

    Deployment model (the one chosen for this implementation — see the ADR):
    the `scan-api` service runs on the *same host* as Zanshin and shares a
    volume with it. Zanshin only ever sends plain filesystem paths over
    HTTP, never file contents — the service reads/writes directly on the
    shared volume. This is what removes Zanshin's own need for Docker socket
    access (the sidecar is the one with Syft/Grype/gitleaks/checkov
    installed), at the cost of an operational requirement: both processes
    must mount the same directory at the same path. `get_workspace_root()`
    is how `ScanProcessor` learns where that shared directory is.
    """

    def __init__(
        self,
        base_url: str,
        shared_workspace_root: Optional[str] = None,
        http_post=httpx.post,
    ):
        self.base_url = base_url.rstrip("/")
        self._shared_workspace_root = shared_workspace_root or None
        # One-off calls (not a persistent httpx.Client), same reasoning as
        # EnrichmentService/OsvScannerEngine: this engine is rebuilt on
        # essentially every request via IoCContainer regardless of whether a
        # scan actually happens, so a client opened in __init__ would leak
        # connections over the app's lifetime far more than it would ever
        # save from reuse. Injectable for tests.
        self._http_post = http_post

    def get_workspace_root(self) -> Optional[str]:
        return self._shared_workspace_root

    def _target_path(self, work_dir: str, sub_path: str) -> str:
        return os.path.join(work_dir, sub_path) if sub_path else work_dir

    def _post(self, path: str, json_body: Dict[str, Any]) -> Any:
        response = self._http_post(f"{self.base_url}{path}", json=json_body, timeout=DEFAULT_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()

    def generate_sbom_for_image(self, image_string: str) -> Dict[str, Any]:
        return self._post("/sbom/image", {"image": image_string})

    def generate_sbom_for_directory(self, work_dir: str, sub_path: str) -> Dict[str, Any]:
        return self._post("/sbom/directory", {"path": self._target_path(work_dir, sub_path)})

    def scan_sbom(self, work_dir: str, sbom: Dict[str, Any]) -> Dict[str, Any]:
        # The SBOM travels in the request body (it's already in memory on
        # the Zanshin side, from the call above) rather than as a shared
        # path — simpler than also writing it to the shared volume just to
        # hand back a path, and it's metadata-sized, not a full checkout.
        return self._post("/scan/vulnerabilities", {"sbom": sbom})

    def scan_secrets(self, work_dir: str, sub_path: str = "") -> list:
        return self._post("/scan/secrets", {"path": self._target_path(work_dir, sub_path)})

    def scan_iac(self, work_dir: str, sub_path: str = "") -> list:
        return self._post("/scan/iac", {"path": self._target_path(work_dir, sub_path)})

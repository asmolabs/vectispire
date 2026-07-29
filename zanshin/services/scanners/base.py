from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

class ScannerEngine(ABC):
    """Abstraction over *where* SBOM generation and vulnerability scanning run.

    See docs/architecture/ADR-001-scanner-backends.md. The rest of the
    application (ScanProcessor) only depends on this interface, never on
    Docker/HTTP details directly. Three backends exist: `DockerScannerEngine`
    (ephemeral local containers, the default), `LocalApiScannerEngine` (a
    sidecar HTTP service on the same host, ADR-001 Phase 4), and
    `OsvScannerEngine` (cloud vulnerability matching via OSV.dev, Phase 5).
    """

    @abstractmethod
    def generate_sbom_for_image(self, image_string: str) -> Dict[str, Any]:
        """Generate an SBOM (Syft JSON format) for a container image reference."""
        raise NotImplementedError

    @abstractmethod
    def generate_sbom_for_directory(self, work_dir: str, sub_path: str) -> Dict[str, Any]:
        """Generate an SBOM (Syft JSON format) for a directory already present on disk."""
        raise NotImplementedError

    @abstractmethod
    def scan_sbom(self, work_dir: str, sbom: Dict[str, Any]) -> Dict[str, Any]:
        """Scan an SBOM for known vulnerabilities (Grype JSON format)."""
        raise NotImplementedError

    @abstractmethod
    def scan_secrets(self, work_dir: str, sub_path: str = "") -> list:
        """Scan a directory already on disk for hardcoded secrets.

        Returns a list of findings (gitleaks JSON report format). Only
        meaningful for source-code targets (git repositories) — container
        image scanning does not call this today (see ADR-001, section 5).
        """
        raise NotImplementedError

    @abstractmethod
    def scan_iac(self, work_dir: str, sub_path: str = "") -> list:
        """Scan a directory already on disk for misconfigured
        Infrastructure-as-Code manifests (Terraform, Kubernetes,
        CloudFormation, ...).

        Returns a list of failed-check entries (checkov's own shape). Only
        meaningful for source-code targets, same reasoning as
        `scan_secrets` — see ADR-001, section 5 (Phase 6).
        """
        raise NotImplementedError

    def get_workspace_root(self) -> Optional[str]:
        """Where `ScanProcessor` should create its per-scan temp directory.

        `None` (the default, used by every backend except
        `LocalApiScannerEngine`) means "use the OS default temp location" —
        fine when the backend that reads those files runs in the same
        process/container as Zanshin. `LocalApiScannerEngine` overrides this
        to point at a directory shared with its sidecar service, since that
        service is handed plain filesystem paths, not file uploads (see
        ADR-001 Phase 4).
        """
        return None

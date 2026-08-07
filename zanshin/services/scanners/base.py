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
    def scan_iac(self, work_dir: str, sub_path: str = "") -> Optional[list]:
        """Scan a directory already on disk for misconfigured
        Infrastructure-as-Code manifests (Terraform, Kubernetes,
        CloudFormation, ...).

        Returns a list of failed-check entries (checkov's own shape), or `None` when the
        analysis could not be performed — `[]` is the positive statement "analysed, no
        misconfiguration", and `ScanIngestor` resolves a target's IaC issues on the
        strength of it. See `scan_sast` for the full reasoning.

        Only meaningful for source-code targets, same reasoning as `scan_secrets` — see
        ADR-001, section 5 (Phase 6).
        """
        raise NotImplementedError

    def scan_sast(
        self, work_dir: str, sub_path: str = "", rules_sub_path: str = ""
    ) -> Optional[list]:
        """Scan a directory already on disk for insecure and low-quality code patterns.

        Returns a list of Semgrep `results` entries, or **`None` meaning "this backend
        does not do SAST"** — which is why this one is concrete rather than abstract.

        That distinction is not cosmetic. `ScanIngestor` reconciles a target's issue
        backlog by resolving everything a scanner looked for and did not find, so an
        empty list is a positive statement: *the code was analysed and is clean*. A
        backend that silently returned `[]` because it cannot run Semgrep would resolve
        every past SAST finding on the next scan. `None` says "not looked at", and the
        backlog is left alone.

        `rules_sub_path` is relative to `work_dir`, like `sub_path`: the runner copies
        the rule tree into the workspace so that the directory is reachable by whatever
        actually executes the tool — including a sibling container, which cannot see a
        path that exists only inside Zanshin's own image.
        """
        return None

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

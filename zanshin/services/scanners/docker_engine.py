import json
import logging
import os
from typing import Any, Dict

import docker

from zanshin.services.scanners.base import ScannerEngine

logger = logging.getLogger(__name__)

class DockerScannerEngine(ScannerEngine):
    """Runs Syft/Grype as ephemeral local Docker containers.

    This is the historical (and today's only) execution mode: nothing ever
    leaves the host running Zanshin, but every scan pays the cost of
    starting a fresh container and requires access to the Docker socket.
    """

    SYFT_IMAGE = "anchore/syft:latest"
    GRYPE_IMAGE = "anchore/grype:latest"
    GITLEAKS_IMAGE = "zricethezav/gitleaks:latest"
    GITLEAKS_REPORT_FILENAME = "zanshin-gitleaks-report.json"
    CHECKOV_IMAGE = "bridgecrew/checkov:latest"

    def _docker_client(self):
        return docker.from_env()

    def _docker_socket_volumes(self) -> Dict[str, Dict[str, str]]:
        volumes: Dict[str, Dict[str, str]] = {}
        sockets = [
            "/var/run/docker.sock",
            os.path.expanduser("~/.docker/run/docker.sock"),
        ]
        for s in sockets:
            if os.path.exists(s):
                volumes[os.path.abspath(s)] = {"bind": "/var/run/docker.sock", "mode": "rw"}
                break
        return volumes

    def generate_sbom_for_image(self, image_string: str) -> Dict[str, Any]:
        client = self._docker_client()
        output_bytes = client.containers.run(
            image=self.SYFT_IMAGE,
            command=["registry:" + image_string, "--platform", "linux/amd64", "-o", "json"],
            volumes=self._docker_socket_volumes(),
            remove=True,
            stdout=True,
            stderr=False,
        )
        return json.loads(output_bytes.decode("utf-8"))

    def generate_sbom_for_directory(self, work_dir: str, sub_path: str) -> Dict[str, Any]:
        client = self._docker_client()
        target = f"/src/{sub_path}" if sub_path else "/src"
        output_bytes = client.containers.run(
            image=self.SYFT_IMAGE,
            command=["dir:" + target, "-o", "json"],
            volumes={os.path.abspath(work_dir): {"bind": "/src", "mode": "ro"}},
            remove=True,
            stdout=True,
            stderr=False,
        )
        return json.loads(output_bytes.decode("utf-8"))

    def scan_sbom(self, work_dir: str, sbom: Dict[str, Any]) -> Dict[str, Any]:
        client = self._docker_client()
        sbom_file_path = os.path.join(work_dir, "sbom.json")
        with open(sbom_file_path, "w") as f:
            json.dump(sbom, f)

        output_bytes = client.containers.run(
            image=self.GRYPE_IMAGE,
            command=["sbom:/work/sbom.json", "-o", "json"],
            volumes={os.path.abspath(work_dir): {"bind": "/work", "mode": "ro"}},
            remove=True,
            stdout=True,
            stderr=False,
        )
        return json.loads(output_bytes.decode("utf-8"))

    def scan_secrets(self, work_dir: str, sub_path: str = "") -> list:
        client = self._docker_client()
        source = f"/repo/{sub_path}" if sub_path else "/repo"

        # --no-git: treat the checkout as plain files rather than replaying
        # git history — repos are cloned with `depth=1`, so history-based
        # scanning would miss almost everything anyway.
        # --exit-code=0: gitleaks exits 1 by default when it finds secrets;
        # here that's an expected outcome, not a failed container run, so
        # results are read from the report file instead of the exit code.
        client.containers.run(
            image=self.GITLEAKS_IMAGE,
            command=[
                "detect",
                f"--source={source}",
                "--no-git",
                "--report-format=json",
                f"--report-path=/repo/{self.GITLEAKS_REPORT_FILENAME}",
                "--exit-code=0",
            ],
            volumes={os.path.abspath(work_dir): {"bind": "/repo", "mode": "rw"}},
            remove=True,
            stdout=True,
            stderr=False,
        )

        report_path = os.path.join(work_dir, self.GITLEAKS_REPORT_FILENAME)
        if not os.path.exists(report_path):
            return []
        with open(report_path) as f:
            content = f.read().strip()
        return json.loads(content) if content else []

    def scan_iac(self, work_dir: str, sub_path: str = "") -> list:
        client = self._docker_client()
        target = f"/repo/{sub_path}" if sub_path else "/repo"

        # --soft-fail: checkov exits 1 by default when it finds failed
        # checks — same reasoning as gitleaks's --exit-code=0, a finding is
        # an expected outcome here, not a failed container run.
        try:
            output_bytes = client.containers.run(
                image=self.CHECKOV_IMAGE,
                command=["-d", target, "-o", "json", "--soft-fail", "--compact"],
                volumes={os.path.abspath(work_dir): {"bind": "/repo", "mode": "ro"}},
                remove=True,
                stdout=True,
                stderr=False,
            )
            payload = json.loads(output_bytes.decode("utf-8"))
        except Exception:
            # checkov's exact CLI/output behavior varies across versions and
            # detected frameworks; treat any failure to run or parse as "no
            # IaC findings this time" rather than failing the whole scan.
            logger.exception("checkov IaC scan failed or returned unparsable output — skipping")
            return []

        # checkov returns a single report object when one framework (e.g.
        # terraform) is detected, or a list of report objects when several
        # are (terraform + kubernetes in the same repo, for instance).
        reports = payload if isinstance(payload, list) else [payload]
        failed_checks = []
        for report in reports:
            failed_checks.extend((report.get("results") or {}).get("failed_checks", []))
        return failed_checks

"""One suite, run against every `ScannerEngine` implementation.

`ScannerEngine` promises that the rest of the application can swap backends
without knowing which one runs (ADR-001, section 3). Nothing checked that
promise: each engine had its own tests, so a fix applied to one silently left the
others behind. Two such divergences existed — the sidecar hardcoded
`linux/amd64` while the Docker backend had been made configurable, and it wrote
gitleaks' report inside the scanned tree after the Docker backend stopped doing
so.

Tests here must only assert what the *interface* promises. Anything specific to
one backend (which CLI flags, `docker:` versus `registry:`) belongs in that
backend's own test module — including justified divergences: the sidecar has no
Docker daemon to pull through, so it genuinely cannot use `docker:`.
"""
import json
import os

import pytest

from zanshin.services.scanners.base import ScannerEngine
from zanshin.services.scanners.docker_engine import DockerScannerEngine
from zanshin.services.scanners.local_api_engine import LocalApiScannerEngine
from zanshin.services.scanners.osv_engine import OsvScannerEngine

AUDITED_PLATFORM = "linux/arm64"
SBOM = {"artifacts": [{"name": "libfoo", "version": "1.0", "purl": "pkg:deb/libfoo@1.0"}]}
GRYPE_OUTPUT = {"matches": [{"vulnerability": {"id": "CVE-1", "severity": "High"}, "artifact": {}}]}
GITLEAKS_REPORT = [{"RuleID": "aws-key", "File": "app.py"}]
CHECKOV_OUTPUT = {"results": {"failed_checks": [{"check_id": "CKV_AWS_1"}]}}


class _FakeDockerHarness:
    """Docker backend with the daemon replaced. Every scanner returns valid
    output for the step being exercised."""

    name = "docker"

    def build(self):
        engine = DockerScannerEngine(image_scan_platform=AUDITED_PLATFORM)
        self.commands = []
        harness = self

        class FakeContainer:
            def __init__(self, command):
                self.command = command

            def start(self):
                # gitleaks writes its report to a path given on the command line;
                # reproduce that so the engine has something to read back.
                for argument in self.command:
                    if isinstance(argument, str) and argument.startswith("--report-path="):
                        path = argument.split("=", 1)[1].replace("/repo", harness.work_dir, 1)
                        with open(path, "w") as f:
                            json.dump(GITLEAKS_REPORT, f)

            def wait(self, timeout=None):
                return {"StatusCode": 0}

            def logs(self, stdout=True, stderr=True):
                if stderr and not stdout:
                    return b""
                return json.dumps(harness._output_for(self.command)).encode()

            def remove(self, force=False):
                pass

        class FakeContainers:
            def create(self, image, command, volumes):
                harness.commands.append((image, command))
                return FakeContainer(command)

        class FakeClient:
            containers = FakeContainers()

        engine._docker_client = lambda: FakeClient()
        return engine

    def _output_for(self, command):
        joined = " ".join(str(c) for c in command)
        if "sbom:" in joined:
            return GRYPE_OUTPUT
        if joined.startswith("-d "):
            return CHECKOV_OUTPUT
        return SBOM

    def image_request(self):
        """What the engine asked of the outside world, for the platform check."""
        return " ".join(str(c) for c in self.commands[0][1])


class _FakeLocalApiHarness:
    name = "local_api"

    def build(self):
        self.requests = []
        harness = self

        class FakeResponse:
            def __init__(self, payload):
                self._payload = payload

            def raise_for_status(self):
                pass

            def json(self):
                return self._payload

        def fake_post(url, json=None, timeout=None):
            harness.requests.append((url, json))
            if url.endswith("/sbom/image") or url.endswith("/sbom/directory"):
                return FakeResponse(SBOM)
            if url.endswith("/scan/vulnerabilities"):
                return FakeResponse(GRYPE_OUTPUT)
            if url.endswith("/scan/secrets"):
                return FakeResponse(GITLEAKS_REPORT)
            return FakeResponse([CHECKOV_OUTPUT["results"]["failed_checks"][0]])

        return LocalApiScannerEngine(
            base_url="http://localhost:8686",
            shared_workspace_root=self.work_dir,
            image_scan_platform=AUDITED_PLATFORM,
            http_post=fake_post,
        )

    def image_request(self):
        return json.dumps(self.requests[0][1])


class _FakeOsvHarness:
    """OSV delegates SBOM/secrets/IaC to a local engine and only replaces
    vulnerability matching, so it is wrapped around the Docker harness."""

    name = "osv"

    def build(self):
        self._inner = _FakeDockerHarness()
        self._inner.work_dir = self.work_dir
        local = self._inner.build()

        class FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {
                    "vulns": [
                        {
                            "id": "GHSA-x",
                            "aliases": ["CVE-1"],
                            "database_specific": {"severity": "HIGH"},
                            "affected": [{"ranges": [{"events": [{"fixed": "1.1"}]}]}],
                        }
                    ]
                }

        return OsvScannerEngine(local_engine=local, http_post=lambda *a, **k: FakeResponse())

    def image_request(self):
        return self._inner.image_request()


HARNESSES = [_FakeDockerHarness, _FakeLocalApiHarness, _FakeOsvHarness]


@pytest.fixture(params=HARNESSES, ids=[h.name for h in HARNESSES])
def engine_case(request, tmp_path):
    harness = request.param()
    harness.work_dir = str(tmp_path)
    engine = harness.build()
    return engine, harness


# --- The interface itself ---

def test_every_engine_implements_the_whole_interface(engine_case):
    engine, _ = engine_case
    assert isinstance(engine, ScannerEngine)
    for method in (
        "generate_sbom_for_image",
        "generate_sbom_for_directory",
        "scan_sbom",
        "scan_secrets",
        "scan_iac",
        "get_workspace_root",
    ):
        assert callable(getattr(engine, method))


def test_workspace_root_is_a_path_or_none(engine_case):
    """`ScanProcessor` uses `None` to mean "the OS temp directory"; anything
    else must be a usable path."""
    engine, _ = engine_case
    root = engine.get_workspace_root()
    assert root is None or isinstance(root, str)


# --- Output shapes the pipeline depends on ---

def test_image_sbom_is_a_dict(engine_case):
    engine, _ = engine_case
    assert isinstance(engine.generate_sbom_for_image("nginx:latest"), dict)


def test_directory_sbom_is_a_dict(engine_case):
    engine, harness = engine_case
    assert isinstance(engine.generate_sbom_for_directory(harness.work_dir, "source"), dict)


def test_vulnerability_scan_returns_a_matches_dict(engine_case):
    """`ScanProcessor._build_findings` and `_summarize_findings` read
    `{"matches": [...]}` whatever produced it — that shared shape is what makes
    the backends interchangeable."""
    engine, harness = engine_case
    result = engine.scan_sbom(harness.work_dir, SBOM)

    assert isinstance(result, dict)
    assert isinstance(result.get("matches"), list)


def test_secret_scan_returns_a_list(engine_case):
    engine, harness = engine_case
    os.makedirs(os.path.join(harness.work_dir, "source"), exist_ok=True)
    assert isinstance(engine.scan_secrets(harness.work_dir, "source"), list)


def test_iac_scan_returns_a_list(engine_case):
    engine, harness = engine_case
    os.makedirs(os.path.join(harness.work_dir, "source"), exist_ok=True)
    assert isinstance(engine.scan_iac(harness.work_dir, "source"), list)


# --- Shared behaviour, once divergent ---

def test_every_engine_audits_the_configured_platform(engine_case):
    """The concrete divergence this suite was written for: the sidecar ignored
    `image_scan_platform` and hardcoded linux/amd64, so switching backends
    silently changed which architecture was being audited — and therefore which
    CVEs were found."""
    engine, harness = engine_case
    engine.generate_sbom_for_image("nginx:latest")

    assert AUDITED_PLATFORM in harness.image_request()


def test_no_engine_writes_into_the_scanned_directory(engine_case):
    """Artefacts belong in the workspace root, never in the tree being scanned
    (see SOURCE_SUBDIR): a gitleaks report holds every detected secret in
    cleartext, and anything left in `source/` is read back by the SBOM, IaC and
    AI-review steps."""
    engine, harness = engine_case
    source_dir = os.path.join(harness.work_dir, "source")
    os.makedirs(source_dir, exist_ok=True)

    engine.scan_secrets(harness.work_dir, "source")
    engine.scan_sbom(harness.work_dir, SBOM)

    assert os.listdir(source_dir) == []

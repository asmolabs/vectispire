import json
import os
import tempfile

import pytest
import requests

from zanshin.services.scanners.docker_engine import (
    DEFAULT_IMAGE_SCAN_PLATFORM,
    DockerScannerEngine,
    ScannerExecutionError,
    ScannerTimeoutError,
)


class FakeContainer:
    """Stands in for a real container: the engine creates it, starts it,
    waits on it, then reads stdout and stderr as *separate* log calls (see
    DockerScannerEngine._run_container)."""

    def __init__(self, stdout=b"", stderr=b"", exit_code=0, on_start=None, wait_error=None):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self._on_start = on_start
        self._wait_error = wait_error
        self.removed = False
        self.killed = False
        self.wait_timeout = None

    def start(self):
        if self._on_start:
            self._on_start()

    def wait(self, timeout=None):
        # The engine passes a timeout so a hung scanner can't hold a worker
        # forever; recorded here so tests can assert it is applied.
        self.wait_timeout = timeout
        if self._wait_error is not None:
            raise self._wait_error
        return {"StatusCode": self.exit_code}

    def kill(self):
        self.killed = True

    def logs(self, stdout=True, stderr=True):
        if stdout and not stderr:
            return self.stdout
        if stderr and not stdout:
            return self.stderr
        return self.stdout + self.stderr

    def remove(self, force=False):
        self.removed = True


class FakeContainers:
    def __init__(self, stdout=b"", stderr=b"", exit_code=0, on_start=None, wait_error=None):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.on_start = on_start
        self.wait_error = wait_error
        self.calls = []
        self.created = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        container = FakeContainer(
            self.stdout, self.stderr, self.exit_code, self.on_start, self.wait_error
        )
        self.created.append(container)
        return container


class FakeClient:
    def __init__(self, stdout=b"", stderr=b"", exit_code=0, on_start=None, wait_error=None):
        self.containers = FakeContainers(stdout, stderr, exit_code, on_start, wait_error)


@pytest.fixture()
def engine():
    return DockerScannerEngine()


def test_generate_sbom_for_image_parses_syft_json(engine):
    payload = {"artifacts": [{"name": "foo"}]}
    fake_client = FakeClient(json.dumps(payload).encode("utf-8"))
    engine._docker_client = lambda: fake_client

    result = engine.generate_sbom_for_image("nginx:latest")

    assert result == payload
    command = fake_client.containers.calls[0]["command"]
    # `docker:` (via the daemon), not `registry:` — syft's own registry
    # client truncates cross-platform layer downloads.
    assert command[0] == "docker:nginx:latest"


def test_generate_sbom_for_image_always_pins_the_audited_platform(engine):
    """Without --platform the daemon returns the host architecture, so the
    SBOM would silently describe a variant nobody asked to audit."""
    fake_client = FakeClient(json.dumps({"artifacts": []}).encode("utf-8"))
    engine._docker_client = lambda: fake_client

    engine.generate_sbom_for_image("nginx:latest")

    command = fake_client.containers.calls[0]["command"]
    assert "--platform" in command
    assert command[command.index("--platform") + 1] == DEFAULT_IMAGE_SCAN_PLATFORM


def test_generate_sbom_for_image_uses_the_configured_platform():
    configured = DockerScannerEngine(image_scan_platform="linux/arm64")
    fake_client = FakeClient(json.dumps({"artifacts": []}).encode("utf-8"))
    configured._docker_client = lambda: fake_client

    configured.generate_sbom_for_image("nginx:latest")

    command = fake_client.containers.calls[0]["command"]
    assert command[command.index("--platform") + 1] == "linux/arm64"


@pytest.mark.parametrize("blank", ["", "   ", None])
def test_blank_platform_never_reaches_syft_as_an_empty_flag(blank):
    """An empty --platform is worse than no setting: syft would accept it and
    the daemon would fall back to the host architecture."""
    lenient = DockerScannerEngine(image_scan_platform=blank)
    fake_client = FakeClient(json.dumps({"artifacts": []}).encode("utf-8"))
    lenient._docker_client = lambda: fake_client

    lenient.generate_sbom_for_image("nginx:latest")

    command = fake_client.containers.calls[0]["command"]
    assert command[command.index("--platform") + 1] == DEFAULT_IMAGE_SCAN_PLATFORM


def test_generate_sbom_for_directory_parses_syft_json(engine, tmp_path):
    payload = {"artifacts": []}
    fake_client = FakeClient(json.dumps(payload).encode("utf-8"))
    engine._docker_client = lambda: fake_client

    result = engine.generate_sbom_for_directory(str(tmp_path), "sub/dir")

    assert result == payload
    command = fake_client.containers.calls[0]["command"]
    assert command[0] == "dir:/src/sub/dir"


def test_scan_sbom_writes_sbom_file_and_parses_grype_json(engine, tmp_path):
    payload = {"matches": [{"vulnerability": {"id": "CVE-1"}}]}
    fake_client = FakeClient(json.dumps(payload).encode("utf-8"))
    engine._docker_client = lambda: fake_client

    result = engine.scan_sbom(str(tmp_path), {"artifacts": []})

    assert result == payload
    assert os.path.exists(os.path.join(tmp_path, "sbom.json"))


def test_scan_secrets_reads_gitleaks_report_file(engine, tmp_path):
    report = [{"RuleID": "aws-access-token", "File": "config.py"}]

    def write_report():
        with open(os.path.join(str(tmp_path), engine.GITLEAKS_REPORT_FILENAME), "w") as f:
            json.dump(report, f)

    engine._docker_client = lambda: FakeClient(on_start=write_report)

    result = engine.scan_secrets(str(tmp_path))

    assert result == report


def test_scan_secrets_returns_empty_list_when_no_report_file(engine, tmp_path):
    engine._docker_client = lambda: FakeClient()
    assert engine.scan_secrets(str(tmp_path)) == []


def test_scan_secrets_returns_empty_list_when_report_file_is_empty(engine, tmp_path):
    def write_empty_report():
        with open(os.path.join(str(tmp_path), engine.GITLEAKS_REPORT_FILENAME), "w") as f:
            f.write("")

    engine._docker_client = lambda: FakeClient(on_start=write_empty_report)

    assert engine.scan_secrets(str(tmp_path)) == []


def test_scan_iac_handles_dict_shaped_checkov_output(engine, tmp_path):
    payload = json.dumps({
        "results": {
            "failed_checks": [
                {"check_id": "CKV_AWS_20", "resource": "aws_s3_bucket.foo", "file_path": "/main.tf", "severity": "HIGH"},
            ]
        }
    })
    engine._docker_client = lambda: FakeClient(payload.encode("utf-8"))

    result = engine.scan_iac(str(tmp_path))

    assert len(result) == 1
    assert result[0]["check_id"] == "CKV_AWS_20"


def test_scan_iac_handles_list_shaped_checkov_output_multiple_frameworks(engine, tmp_path):
    payload = json.dumps([
        {"results": {"failed_checks": [{"check_id": "CKV_K8S_1"}]}},
        {"results": {"failed_checks": [{"check_id": "CKV_AWS_99"}]}},
    ])
    engine._docker_client = lambda: FakeClient(payload.encode("utf-8"))

    result = engine.scan_iac(str(tmp_path))

    assert {c["check_id"] for c in result} == {"CKV_K8S_1", "CKV_AWS_99"}


def test_scan_iac_returns_empty_list_on_malformed_output(engine, tmp_path):
    engine._docker_client = lambda: FakeClient(b"not valid json {{{")

    assert engine.scan_iac(str(tmp_path)) == []


# --- stderr propagation -----------------------------------------------------
# The whole point of running containers detached and reading the streams
# apart: whatever the scanner said on stderr has to reach `Scan.error`,
# which is what ScanProcessor fills from `str(exception)`.


def test_scanner_stderr_reaches_the_exception_on_nonzero_exit(engine):
    stderr = b"[0143] ERROR could not determine source: unexpected EOF"
    engine._docker_client = lambda: FakeClient(stdout=b"", stderr=stderr, exit_code=1)

    with pytest.raises(ScannerExecutionError) as excinfo:
        engine.generate_sbom_for_image("nginx:latest")

    message = str(excinfo.value)
    assert "could not determine source" in message
    assert "code 1" in message
    assert excinfo.value.stderr == stderr


def test_scanner_stderr_reaches_the_exception_when_stdout_is_not_json(engine):
    """The case that used to be undiagnosable: the tool exits 0, so nothing
    looks wrong, but stdout isn't the JSON we asked for."""
    engine._docker_client = lambda: FakeClient(
        stdout=b"panic: runtime error", stderr=b"warning: catalogers skipped", exit_code=0
    )

    with pytest.raises(ScannerExecutionError) as excinfo:
        engine.generate_sbom_for_image("nginx:latest")

    assert "catalogers skipped" in str(excinfo.value)


def test_stdout_stays_clean_when_the_scanner_also_writes_to_stderr(engine):
    """stderr must never be folded into the payload — that's exactly what
    `stderr=False` on containers.run() used to protect against."""
    payload = {"artifacts": [{"name": "foo"}]}
    engine._docker_client = lambda: FakeClient(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"[0001] WARN some cataloger was skipped",
    )

    assert engine.generate_sbom_for_image("nginx:latest") == payload


def test_the_whole_scanner_output_reaches_the_error_message(engine):
    """`Scan.error` is `Text` since migration 0003, so nothing is trimmed.

    This replaces two tests that asserted the opposite — that the message fit
    inside 255 characters, at the cost of cutting either the scanner's words or
    the label. Scanner output is the one thing you never want truncated, so the
    column was widened and the budget-splitting logic deleted.
    """
    long_stderr = "ERROR could not determine source: " + "detail " * 200
    engine._docker_client = lambda: FakeClient(
        stdout=b"", stderr=long_stderr.encode(), exit_code=1
    )

    with pytest.raises(ScannerExecutionError) as excinfo:
        engine.generate_sbom_for_image("registry.example.com:5000/" + "ns/" * 12 + "img:tag")

    message = str(excinfo.value)
    assert len(message) > 255  # no longer capped
    assert "could not determine source" in message
    assert message.rstrip().endswith("detail")  # ...and it is not cut short
    # The label survives in full too, however long the image reference is.
    assert "registry.example.com:5000" in message
    assert "img:tag" in message


def test_an_empty_stderr_still_produces_a_readable_reason(engine):
    engine._docker_client = lambda: FakeClient(stdout=b"", stderr=b"", exit_code=2)

    with pytest.raises(ScannerExecutionError) as excinfo:
        engine.generate_sbom_for_image("nginx:latest")

    message = str(excinfo.value)
    assert "code 2" in message
    assert "aucune sortie d'erreur" in message


def test_container_is_removed_even_when_the_scanner_fails(engine):
    fake_client = FakeClient(stdout=b"", stderr=b"boom", exit_code=1)
    engine._docker_client = lambda: fake_client

    with pytest.raises(ScannerExecutionError):
        engine.generate_sbom_for_image("nginx:latest")

    assert fake_client.containers.created[0].removed is True


def test_gitleaks_hard_failure_raises_rather_than_reporting_no_secrets(engine, tmp_path):
    """gitleaks runs with --exit-code=0, so a non-zero exit is a real
    failure, not "found secrets" — it must not be mistaken for a clean scan."""
    engine._docker_client = lambda: FakeClient(stderr=b"failed to open source path", exit_code=2)

    with pytest.raises(ScannerExecutionError) as excinfo:
        engine.scan_secrets(str(tmp_path))

    assert "failed to open source path" in str(excinfo.value)


# --- Timeouts (a hung scanner used to hold a scan-pool worker forever) ---

def test_the_configured_timeout_is_applied_to_the_container_wait(engine):
    client = FakeClient(stdout=b'{"artifacts": []}')
    engine._docker_client = lambda: client
    engine.timeout_seconds = 42

    engine.generate_sbom_for_directory("/tmp/x", "")

    assert client.containers.created[0].wait_timeout == 42


def test_a_timed_out_scanner_is_killed_and_reported_as_a_timeout(engine):
    """Without this, a stalled image pull kept one of the five scan workers
    busy for the lifetime of the process — and the scan stayed "scanning"
    forever, which the issue lifecycle then reads as the target's latest state."""
    client = FakeClient(
        stderr=b"pulling image",
        wait_error=requests.exceptions.ReadTimeout("read timed out"),
    )
    engine._docker_client = lambda: client
    engine.timeout_seconds = 5

    with pytest.raises(ScannerTimeoutError) as excinfo:
        engine.generate_sbom_for_image("nginx:latest")

    container = client.containers.created[0]
    assert container.killed is True
    assert container.removed is True  # cleanup still happens
    assert "5 s" in str(excinfo.value)
    # The tool's own output survives into the message, as for other failures.
    assert "pulling image" in str(excinfo.value)


def test_a_daemon_failure_is_not_mistaken_for_a_timeout(engine):
    """A dead Docker socket must not be reported as "the scanner was too slow" —
    the operator would look in the wrong place."""
    client = FakeClient(wait_error=requests.exceptions.ConnectionError("socket refused"))
    engine._docker_client = lambda: client

    with pytest.raises(requests.exceptions.ConnectionError):
        engine.generate_sbom_for_image("nginx:latest")


# --- Supply chain and container hardening (security review S6/S7) ---

def test_every_scanner_image_is_pinned_by_digest(engine):
    """These four images run on the host with the Docker socket mounted: whoever
    controls `anchore/syft:latest` controls this machine. A moving tag also makes
    a scan unreproducible."""
    for image in (engine.SYFT_IMAGE, engine.GRYPE_IMAGE, engine.GITLEAKS_IMAGE, engine.CHECKOV_IMAGE):
        assert "@sha256:" in image, image
        assert ":latest" not in image, image


def test_containers_run_with_capabilities_dropped_and_ceilings(engine):
    client = FakeClient(stdout=b'{"artifacts": []}')
    engine._docker_client = lambda: client

    engine.generate_sbom_for_directory("/tmp/x", "source")

    kwargs = client.containers.calls[0]
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges"]
    assert kwargs["mem_limit"]
    assert kwargs["pids_limit"] > 0


@pytest.mark.parametrize(
    ("step", "args", "network_expected"),
    [
        # gitleaks, checkov and a directory SBOM have nothing to fetch.
        ("generate_sbom_for_directory", ("/tmp/x", "source"), False),
        # Grype downloads its vulnerability database; syft pulls the image.
        ("scan_sbom", ("/tmp/x", {"artifacts": []}), True),
        ("generate_sbom_for_image", ("nginx:latest",), True),
    ],
)
def test_the_network_is_only_available_where_a_tool_needs_it(engine, tmp_path, step, args, network_expected):
    client = FakeClient(stdout=b'{"artifacts": []}')
    engine._docker_client = lambda: client
    if step == "scan_sbom":
        args = (str(tmp_path), {"artifacts": []})

    getattr(engine, step)(*args)

    kwargs = client.containers.calls[0]
    assert kwargs["network_disabled"] is (not network_expected)


def test_secret_and_iac_scanners_never_get_the_network(engine, tmp_path):
    """A scanner that reads secrets and has no reason to reach the network should
    not be able to."""
    (tmp_path / "source").mkdir()
    for step in ("scan_secrets", "scan_iac"):
        client = FakeClient(stdout=b"[]")
        engine._docker_client = lambda c=client: c
        getattr(engine, step)(str(tmp_path), "source")
        assert client.containers.calls[0]["network_disabled"] is True, step

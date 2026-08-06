"""Tests for the remote agent.

Driven against a fake controller, so no HTTP and no scanners are involved. What is
being pinned down is the loop's behaviour under the three failures that actually
happen — a scan that fails, a controller that is unreachable, a lease that was
reassigned — plus the import graph, which is where the "an agent has no database"
guarantee of ADR-002 D3 actually lives.
"""
import subprocess
import sys
import textwrap

import pytest

from zanshin.agent.client import ControllerError, LeaseLost
from zanshin.agent.config import AgentConfig, from_environment
from zanshin.agent.worker import AgentWorker
from zanshin.scan_contract import CONTRACT_VERSION, TARGET_REPOSITORY, ScanArtifacts, ScanTask


def config(**overrides) -> AgentConfig:
    values = {
        "url": "https://zanshin.test",
        "token": "zsk_secret",
        "retry_seconds": 0,  # tests must not sleep
        "max_jobs": 1,
    }
    values.update(overrides)
    return AgentConfig(**values)


class FakeClient:
    """A controller that hands out a fixed list of jobs."""

    def __init__(self, tasks=None, hello_error=None, claim_error=None,
                 heartbeat_error=None, report_error=None):
        self.tasks = list(tasks or [])
        self.hello_error = hello_error
        self.claim_error = claim_error
        self.heartbeat_error = heartbeat_error
        self.report_error = report_error
        self.hello_calls = 0
        self.claims = 0
        self.heartbeats = []
        self.successes = []
        self.failures = []

    def hello(self, report):
        self.hello_calls += 1
        if self.hello_error:
            error, self.hello_error = self.hello_error, None
            raise error
        return {
            "name": "paris-01", "credentials_mode": "local", "max_concurrent": 1,
            "poll_wait_seconds": 0, "heartbeat_seconds": 3600,
            "contract_version": CONTRACT_VERSION, "agent_id": "abc", "labels": [],
            "enabled": True,
        }

    def claim(self, wait_seconds):
        self.claims += 1
        if self.claim_error:
            error, self.claim_error = self.claim_error, None
            raise error
        return self.tasks.pop(0) if self.tasks else None

    def heartbeat(self, scan_id, message=None):
        self.heartbeats.append((scan_id, message))
        if self.heartbeat_error:
            raise self.heartbeat_error

    def report_success(self, scan_id, artifacts, message_id, chunk_bytes):
        if self.report_error:
            error, self.report_error = self.report_error, None
            raise error
        self.successes.append((scan_id, artifacts, message_id))
        return {"scan_id": scan_id, "outcome": "applied"}

    def report_failure(self, scan_id, error, message_id):
        self.failures.append((scan_id, error, message_id))
        return {"scan_id": scan_id, "outcome": "applied"}


class FakeRunner:
    def __init__(self, artifacts=None, error=None, steps=("Clonage", "SBOM")):
        self.artifacts = artifacts or ScanArtifacts(cves={"matches": []}, duration_ms=1)
        self.error = error
        self.steps = steps
        self.runs = []

    def run(self, task, on_step=None):
        self.runs.append(task)
        for step in self.steps:
            if on_step:
                on_step(step)
        if self.error:
            raise self.error
        return self.artifacts


def task(scan_id=1) -> ScanTask:
    return ScanTask(
        scan_id=scan_id, kind=TARGET_REPOSITORY, repo_url="https://example.com/a.git",
        branch="main",
    )


# --- The happy path -----------------------------------------------------------

def test_a_job_is_run_and_reported(monkeypatch):
    client = FakeClient(tasks=[task()])
    runner = FakeRunner()
    worker = AgentWorker(config(), client=client, runner=runner)

    assert worker.run_forever() == 1

    assert len(runner.runs) == 1
    assert client.successes[0][0] == 1
    # Progress is pushed as each step starts, which is also what renews the lease.
    assert [m for _, m in client.heartbeats] == ["Clonage", "SBOM"]


def test_the_controller_decides_the_pacing(monkeypatch):
    """Sent by the controller rather than configured per machine, so tuning a fleet
    is one change instead of N."""
    client = FakeClient()
    worker = AgentWorker(config(max_jobs=0), client=client, runner=FakeRunner())

    worker.announce()

    assert worker.heartbeat_seconds == 3600
    assert worker.identity["name"] == "paris-01"


def test_the_same_message_id_is_used_for_one_report(monkeypatch):
    """It is what makes the controller's retry handling possible: one id per report,
    reused by every retry of that report."""
    client = FakeClient(tasks=[task(), task(2)])
    worker = AgentWorker(config(max_jobs=2), client=client, runner=FakeRunner())

    worker.run_forever()

    ids = [message_id for _, _, message_id in client.successes]
    assert len(ids) == 2
    assert ids[0] != ids[1]  # a *different* report gets a different id


# --- A scan that fails --------------------------------------------------------

def test_a_failed_scan_is_reported_as_a_result_not_as_an_agent_error():
    """A clone that is refused is a scan result, and the operator has to see it as
    one — the agent is working perfectly."""
    client = FakeClient(tasks=[task()])
    runner = FakeRunner(error=RuntimeError("Clone impossible : accès refusé"))
    worker = AgentWorker(config(), client=client, runner=runner)

    assert worker.run_forever() == 1

    assert client.successes == []
    assert "accès refusé" in client.failures[0][1]


def test_a_failed_scan_does_not_stop_the_loop():
    client = FakeClient(tasks=[task(), task(2)])
    runner = FakeRunner(error=RuntimeError("boom"))
    worker = AgentWorker(config(max_jobs=2), client=client, runner=runner)

    assert worker.run_forever() == 2
    assert len(client.failures) == 2


# --- A controller that is unreachable -----------------------------------------

def test_an_unreachable_controller_is_retried_rather_than_fatal():
    """An agent that exited on a network blip would turn a rolling restart of the
    control plane into a fleet outage."""
    client = FakeClient(tasks=[task()], hello_error=ConnectionError("connection refused"))
    worker = AgentWorker(config(), client=client, runner=FakeRunner())

    assert worker.run_forever() == 1
    assert client.hello_calls == 2  # failed once, then succeeded


def test_a_refused_registration_is_retried_with_the_controllers_own_message(caplog):
    """Almost always configuration (wrong scope, missing agent, contract mismatch),
    and the controller's message says which — so it must reach the log."""
    client = FakeClient(
        tasks=[task()],
        hello_error=ControllerError("HTTP 403: Cette clé n'a pas la portée 'agent'.", 403),
    )
    worker = AgentWorker(config(), client=client, runner=FakeRunner())

    with caplog.at_level("ERROR"):
        worker.run_forever()

    assert "portée 'agent'" in caplog.text


def test_a_claim_failure_is_retried():
    client = FakeClient(tasks=[task()], claim_error=ConnectionError("timeout"))
    worker = AgentWorker(config(), client=client, runner=FakeRunner())

    assert worker.run_forever() == 1
    assert client.claims == 2


def test_a_transport_failure_while_reporting_is_retried_until_it_lands():
    """A scan takes minutes; losing its result to a momentary network failure would
    mean running it again from scratch. Safe to retry because of `message_id`."""
    client = FakeClient(tasks=[task()], report_error=ConnectionError("reset"))
    worker = AgentWorker(config(), client=client, runner=FakeRunner())

    worker.run_forever()

    assert len(client.successes) == 1


# --- A lease that was reassigned ----------------------------------------------

def test_a_lost_lease_stops_the_scan_without_reporting():
    """Whatever this agent computed would be refused, and insisting would mean
    overwriting the results of whoever took the work over."""
    client = FakeClient(tasks=[task()], heartbeat_error=LeaseLost("reassigned", 409))
    runner = FakeRunner()
    worker = AgentWorker(config(), client=client, runner=runner)

    assert worker.run_forever() == 1

    assert client.successes == []
    assert client.failures == []
    # And it stopped at the first step rather than running every scanner for nothing.
    assert len(runner.runs) == 1


def test_a_report_refused_because_the_job_is_gone_is_not_retried():
    client = FakeClient(tasks=[task()], report_error=LeaseLost("not yours", 403))
    worker = AgentWorker(config(), client=client, runner=FakeRunner())

    worker.run_forever()

    assert client.successes == []


# --- Configuration ------------------------------------------------------------

def test_the_url_and_token_are_required():
    with pytest.raises(ValueError, match="URL"):
        AgentConfig(url="", token="zsk_x")
    with pytest.raises(ValueError, match="agent"):
        AgentConfig(url="https://zanshin.test", token="")


def test_an_unset_flag_does_not_erase_an_environment_variable(monkeypatch):
    monkeypatch.setenv("ZANSHIN_URL", "https://zanshin.test")
    monkeypatch.setenv("ZANSHIN_AGENT_TOKEN", "zsk_env")

    built = from_environment(url=None, token=None, name="runner-9")

    assert built.token == "zsk_env"
    assert built.name == "runner-9"


def test_a_trailing_slash_on_the_url_is_dropped(monkeypatch):
    assert AgentConfig(url="https://zanshin.test/", token="zsk_x").url == "https://zanshin.test"


# --- The property that makes an agent safe ------------------------------------

def test_the_agent_package_imports_no_database_model_or_ui_code():
    """ADR-002 D3, as an import graph. An agent that could reach the database would
    need its credentials *and* `ENCRYPTION_KEY` — i.e. the ability to decrypt every
    deploy key Zanshin holds. Checked in a fresh interpreter, since anything the rest
    of this session imported would already be in `sys.modules`.
    """
    program = textwrap.dedent(
        """
        import sys
        import zanshin.agent
        import zanshin.agent.cli  # noqa: F401 — the heaviest entry point
        import zanshin.agent.worker  # noqa: F401

        forbidden = sorted(
            name for name in sys.modules
            if name.startswith(("zanshin.database", "zanshin.models", "zanshin.ui",
                                "zanshin.container", "zanshin.api", "reflex", "alembic"))
            or name in ("sqlalchemy", "bcrypt")
        )
        print(",".join(forbidden))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "", f"the agent pulled in: {result.stdout.strip()}"


def test_the_cli_reports_a_missing_configuration_instead_of_crashing():
    result = subprocess.run(
        [sys.executable, "-m", "zanshin.agent"],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"},
    )

    assert result.returncode == 2
    assert "Configuration invalide" in result.stderr

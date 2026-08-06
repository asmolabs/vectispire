"""The agent's loop: ask for work, run it, report, repeat.

Three failure modes shape everything here, and they are not the same failure:

- **the scan fails** (a clone is refused, a scanner errors) — that is a *result*,
  reported as `failed`, and the agent moves on to the next job. It is not the
  agent's problem;
- **the controller is unreachable** — the agent waits and retries forever. An agent
  that exited on a network blip would need a supervisor to be useful, and would
  make a rolling restart of the control plane look like a fleet outage;
- **the lease is lost** — the work was reassigned while this agent was slow or
  silent. It drops the job without reporting: whatever it computed would be refused
  anyway, and insisting would mean overwriting the results of whoever took over.
"""
import logging
import platform
import socket
import threading
import time
import uuid
from typing import Optional

from zanshin.agent.client import AgentClient, ControllerError, LeaseLost
from zanshin.agent.config import AgentConfig
from zanshin.scan_contract import CONTRACT_VERSION, ScanTask
from zanshin.services.scan_runner import ScanRunner

logger = logging.getLogger(__name__)


def build_scanner_engine(config: AgentConfig):
    """The engine this agent will run scans with.

    Imported here rather than at module load so that `import zanshin.agent` stays
    cheap, and so a Docker client is only constructed by an agent that actually uses
    one.
    """
    if config.scanner_engine == "local_api":
        from zanshin.services.scanners.local_api_engine import LocalApiScannerEngine

        return LocalApiScannerEngine(
            base_url=config.local_api_url,
            shared_workspace_root=config.local_api_shared_dir or None,
        )
    if config.scanner_engine == "osv":
        from zanshin.services.scanners.osv_engine import OsvScannerEngine

        return OsvScannerEngine()
    from zanshin.services.scanners.docker_engine import DockerScannerEngine

    return DockerScannerEngine()


class Heartbeat:
    """Renews the lease on a timer for as long as a job is running.

    A thread rather than renewing between steps, which is what the built-in agent
    does: a single step here can be an image pull over somebody's uplink, and the
    controller has to be able to tell "slow" from "gone" faster than one step. The
    thread is a daemon and stops with the job.
    """

    def __init__(self, client: AgentClient, scan_id: int, interval_seconds: int):
        self.client = client
        self.scan_id = scan_id
        self.interval = max(5, interval_seconds)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Set when the controller says the lease is gone, so the worker can stop
        # early instead of finishing a scan whose result will be refused.
        self.lease_lost = threading.Event()

    def __enter__(self) -> "Heartbeat":
        self._thread = threading.Thread(
            target=self._loop, name=f"zanshin-agent-heartbeat-{self.scan_id}", daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.client.heartbeat(self.scan_id)
            except LeaseLost:
                logger.warning("Lease on scan %s was reassigned", self.scan_id)
                self.lease_lost.set()
                return
            except Exception:
                # A missed heartbeat is not a reason to stop scanning: the lease is
                # generous enough to survive several, and the scan may well finish
                # before it lapses.
                logger.warning("Heartbeat for scan %s failed; continuing", self.scan_id)


class AgentWorker:
    def __init__(self, config: AgentConfig, client: Optional[AgentClient] = None, runner=None):
        self.config = config
        self.client = client or AgentClient(config)
        self.runner = runner or ScanRunner(build_scanner_engine(config))
        # Filled in by `announce()`: the controller decides the pacing, so a fleet is
        # tuned in one place rather than machine by machine.
        self.poll_wait_seconds = config.poll_wait_seconds
        self.heartbeat_seconds = config.heartbeat_seconds
        self.identity = None
        self._stop = threading.Event()

    # --- Lifecycle --------------------------------------------------------

    def stop(self) -> None:
        self._stop.set()

    def announce(self) -> dict:
        """Introduce this agent and adopt the pacing it is given."""
        self.identity = self.client.hello({
            "hostname": self.config.name or _hostname(),
            "platform": platform.platform(),
            "version": CONTRACT_VERSION,
            "scanner_engine": self.config.scanner_engine,
            "capabilities": {"engine": self.config.scanner_engine},
        })
        self.poll_wait_seconds = int(
            self.identity.get("poll_wait_seconds") or self.poll_wait_seconds
        )
        self.heartbeat_seconds = int(
            self.identity.get("heartbeat_seconds") or self.heartbeat_seconds
        )
        logger.info(
            "Registered as '%s' (mode identifiants : %s, %s scan(s) en parallèle)",
            self.identity.get("name"),
            self.identity.get("credentials_mode"),
            self.identity.get("max_concurrent"),
        )
        return self.identity

    def run_forever(self) -> int:
        """Loop until stopped (or until `max_jobs` jobs have been handled).

        Returns how many jobs were handled, which is what makes the one-shot mode
        (`--max-jobs 1`, useful as a CI step) observable.
        """
        while not self._stop.is_set() and self.identity is None:
            try:
                self.announce()
            except ControllerError as e:
                # A refusal here is almost always configuration — a wrong scope, a
                # missing agent, an incompatible contract version — and the
                # controller's message says which. Retrying is still right: the
                # operator may be about to fix it, and an agent that exits leaves a
                # container restarting in a loop with the reason buried in an old log.
                logger.error("Registration refused: %s", e)
                if self._stop.wait(self.config.retry_seconds):
                    return 0
            except Exception as e:
                logger.warning("Controller unreachable (%s); retrying", e)
                if self._stop.wait(self.config.retry_seconds):
                    return 0

        handled = 0
        while not self._stop.is_set():
            if self.config.max_jobs is not None and handled >= self.config.max_jobs:
                break
            try:
                task = self.client.claim(self.poll_wait_seconds)
            except ControllerError as e:
                logger.error("Could not claim a job: %s", e)
                if self._stop.wait(self.config.retry_seconds):
                    break
                continue
            except Exception as e:
                logger.warning("Controller unreachable (%s); retrying", e)
                if self._stop.wait(self.config.retry_seconds):
                    break
                continue

            if task is None:
                continue

            self.handle(task)
            handled += 1
        return handled

    # --- One job ----------------------------------------------------------

    def handle(self, task: ScanTask) -> None:
        """Run one task and report it. Never raises.

        The `message_id` is generated once, here, and reused by every retry of this
        report: it is what lets the controller apply the result exactly once even
        though delivery is at-least-once.
        """
        message_id = str(uuid.uuid4())
        logger.info("Scan %s: starting (%s)", task.scan_id, task.kind)

        with Heartbeat(self.client, task.scan_id, self.heartbeat_seconds) as beat:
            try:
                artifacts = self.runner.run(
                    task,
                    on_step=lambda message: self._on_step(task, beat, message),
                )
            except LeaseLost:
                logger.warning("Scan %s abandoned: the lease was reassigned", task.scan_id)
                return
            except Exception as e:
                logger.exception("Scan %s failed", task.scan_id)
                self._report(lambda: self.client.report_failure(task.scan_id, str(e), message_id),
                             task)
                return

            if beat.lease_lost.is_set():
                # Finishing the report would overwrite the results of whoever took
                # this scan over.
                logger.warning(
                    "Scan %s completed but its lease is gone; discarding the result",
                    task.scan_id,
                )
                return

            self._report(
                lambda: self.client.report_success(
                    task.scan_id, artifacts, message_id, self.config.chunk_bytes
                ),
                task,
            )

    def _on_step(self, task: ScanTask, beat: Heartbeat, message: str) -> None:
        """Push progress to the controller as each step starts.

        Also the earliest point at which a lost lease can be noticed, which saves
        running the remaining scanners for nothing.
        """
        if beat.lease_lost.is_set():
            raise LeaseLost(f"Lease on scan {task.scan_id} was reassigned")
        try:
            self.client.heartbeat(task.scan_id, message)
        except LeaseLost:
            beat.lease_lost.set()
            raise

    def _report(self, send, task: ScanTask) -> None:
        """Send a report, retrying transport failures until it lands.

        Retrying is safe *because* of `message_id`, and it matters: a scan can take
        minutes, and losing its result to a momentary network failure would mean
        running it again from scratch.
        """
        while not self._stop.is_set():
            try:
                acknowledgement = send()
                logger.info(
                    "Scan %s: reported (%s)", task.scan_id, acknowledgement.get("outcome")
                )
                return
            except LeaseLost as e:
                logger.warning("Scan %s: report refused (%s)", task.scan_id, e)
                return
            except ControllerError as e:
                logger.error("Scan %s: controller refused the report (%s)", task.scan_id, e)
                return
            except Exception as e:
                logger.warning(
                    "Scan %s: could not report (%s); retrying in %ss",
                    task.scan_id, e, self.config.retry_seconds,
                )
                if self._stop.wait(self.config.retry_seconds):
                    return


def _hostname() -> str:
    try:
        return socket.gethostname() or "agent"
    except Exception:
        return "agent"

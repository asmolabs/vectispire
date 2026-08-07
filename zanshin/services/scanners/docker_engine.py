import json
import logging
import os
from typing import Any, Dict, Optional

import docker
import requests

from zanshin.services.scanners.base import ScannerEngine

logger = logging.getLogger(__name__)

# Wall-clock ceiling for one scanner container.
#
# Without it, a scanner that hangs (an image pull stalled behind a dead
# registry, a pathological repository) holds one of the scan pool's workers for
# the lifetime of the process. Five of those and the application stops scanning
# altogether — silently, since the scan just stays "scanning" forever.
#
# Generous by default: a cold Grype database download plus a large image pull is
# legitimately slow. Environment-tunable rather than a database setting, because
# it has to be right before anything can be configured through the UI.
DEFAULT_CONTAINER_TIMEOUT_SECONDS = int(os.getenv("ZANSHIN_SCAN_TIMEOUT_SECONDS", "900"))

# Ceilings for a scanner container. A scanner is not supposed to need much of
# either; these exist so that a pathological input degrades into a failed scan
# instead of an out-of-memory host or a fork bomb.
SCAN_MEMORY_LIMIT = os.getenv("ZANSHIN_SCAN_MEMORY_LIMIT", "2g")
SCAN_PIDS_LIMIT = int(os.getenv("ZANSHIN_SCAN_PIDS_LIMIT", "512"))

# Which architecture container images are audited as, when the
# `image_scan_platform` setting isn't set (see scanners/factory.py).
# Deliberately *not* the host's architecture: the SBOM — and therefore the
# CVE set — differs per platform, so this is an audit target chosen by the
# operator, not a property of whatever machine happens to run Zanshin.
DEFAULT_IMAGE_SCAN_PLATFORM = "linux/amd64"


def _is_timeout(error: Exception) -> bool:
    """Whether a requests-family error is a read timeout.

    Checked by type first, with a string fallback: docker-py wraps the
    underlying urllib3 timeout differently across versions, and treating a
    genuine daemon failure as a timeout (or vice versa) would report the wrong
    cause on `Scan.error`.
    """
    if isinstance(error, (requests.exceptions.ReadTimeout, requests.exceptions.ConnectTimeout)):
        return True
    return "timed out" in str(error).lower() or "timeout" in type(error).__name__.lower()


def _strip_prefix(path: Optional[str], prefix: str) -> Optional[str]:
    """Container-side path to repository-relative path."""
    if not path:
        return path
    stripped = path[len(prefix):] if path.startswith(prefix) else path
    return stripped.lstrip("/") or path


def _collapse(raw: bytes) -> str:
    """Flattens a container's stderr into a single line."""
    return " ".join(raw.decode("utf-8", errors="replace").split())


def _build_message(label: str, detail: str, reason: str) -> str:
    """Assembles a `<label> <reason> : <detail>` line.

    Used to be a budget splitter that trimmed the label and the scanner's own
    words to fit `Scan.error`'s 255 characters. That column is `Text` since
    migration 0003, so the whole exercise — and the judgement calls about which
    half of the message to sacrifice — is gone. Scanner output is one of the few
    things you never want truncated.
    """
    return f"{label} {reason} : {detail or '(aucune sortie d\'erreur)'}"


class ScannerExecutionError(RuntimeError):
    """A scanner container failed, or produced output that couldn't be read.

    Carries the tool's own stderr into the message so the reason survives
    all the way to `Scan.error` and the UI. Before this existed, the
    stderr stream was discarded outright (see `_run_container`) and a
    failure surfaced as a bare `JSONDecodeError` with no indication of
    what the scanner had complained about.
    """

    def __init__(self, label: str, exit_code: int, stderr: bytes, stdout: bytes = b""):
        self.label = label
        self.exit_code = exit_code
        self.stderr = stderr
        self.stdout = stdout
        detail = _collapse(stderr)
        if exit_code != 0:
            reason = f"a échoué (code {exit_code})"
        else:
            # Exit code 0 but unreadable stdout: the tool thinks it
            # succeeded, so its stderr is where any warning will be.
            reason = "a rendu une sortie illisible"
        super().__init__(_build_message(label, detail, reason))


class ScannerTimeoutError(RuntimeError):
    """A scanner container outlived its timeout and was killed.

    Distinct from `ScannerExecutionError` because the cause is different in kind:
    the tool didn't fail, it never finished. The scan is marked failed with a
    message that says so, instead of hanging forever.
    """

    def __init__(self, label: str, timeout_seconds: int, stderr: bytes = b""):
        self.label = label
        self.timeout_seconds = timeout_seconds
        self.stderr = stderr
        detail = _collapse(stderr)
        super().__init__(
            _build_message(label, detail, f"n'a pas terminé en {timeout_seconds} s (interrompu)")
        )


class DockerScannerEngine(ScannerEngine):
    """Runs Syft/Grype as ephemeral local Docker containers.

    This is the historical (and today's only) execution mode: nothing ever
    leaves the host running Zanshin, but every scan pays the cost of
    starting a fresh container and requires access to the Docker socket.

    `image_scan_platform` picks which architecture container images are
    audited as; it comes from the `image_scan_platform` setting (see
    scanners/factory.py) and falls back to DEFAULT_IMAGE_SCAN_PLATFORM.
    """

    def __init__(
        self,
        image_scan_platform: str = DEFAULT_IMAGE_SCAN_PLATFORM,
        timeout_seconds: int = DEFAULT_CONTAINER_TIMEOUT_SECONDS,
    ):
        # A blank setting row means "unset", not "no platform" — sending an
        # empty --platform to syft would let the daemon fall back to the
        # host architecture, which is exactly what this setting exists to
        # keep explicit.
        self.image_scan_platform = (image_scan_platform or "").strip() or DEFAULT_IMAGE_SCAN_PLATFORM
        self.timeout_seconds = timeout_seconds

    # Pinned by digest, not by tag.
    #
    # These five images *are* Zanshin's supply chain: they run on the host with
    # the Docker socket mounted, so whoever controls `anchore/syft:latest`
    # controls this machine. A moving tag also means a scan is not reproducible —
    # two runs a week apart can disagree and nobody can say why.
    #
    # The digests are the multi-arch index digests (resolved 2026-08-06), so they
    # still select the right architecture per host. Updating them is a deliberate,
    # reviewable act: `docker buildx imagetools inspect <image>:latest`.
    SYFT_IMAGE = os.getenv(
        "ZANSHIN_SYFT_IMAGE",
        "anchore/syft@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026",
    )
    GRYPE_IMAGE = os.getenv(
        "ZANSHIN_GRYPE_IMAGE",
        "anchore/grype@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db",
    )
    GITLEAKS_IMAGE = os.getenv(
        "ZANSHIN_GITLEAKS_IMAGE",
        "zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f",
    )
    CHECKOV_IMAGE = os.getenv(
        "ZANSHIN_CHECKOV_IMAGE",
        "bridgecrew/checkov@sha256:12a62da01af22654883aee3b9da18ba4297f123f5122663bf65235db37934144",
    )
    SEMGREP_IMAGE = os.getenv(
        "ZANSHIN_SEMGREP_IMAGE",
        "semgrep/semgrep@sha256:bdf7013b2c3634a487671158da77c554f531742326b543a9464d2adf6c433ac8",
    )
    GITLEAKS_REPORT_FILENAME = "zanshin-gitleaks-report.json"

    # Fraction of target files Semgrep may fail on before its result is treated as "did
    # not run" rather than "found nothing". Semgrep exits 0 when individual files time
    # out, so a run where most of the repository was skipped is indistinguishable from a
    # clean one by its exit code alone — and reading it as clean would resolve the
    # target's whole SAST backlog.
    SEMGREP_MAX_ERROR_RATIO = 0.25

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

    def _hardening(self, network: bool) -> Dict[str, Any]:
        """Limits applied to every scanner container.

        These containers parse hostile input by definition — an untrusted image's
        metadata, a repository someone else wrote — and the image-SBOM step runs
        with the Docker socket mounted, which is root-equivalent on the host. The
        limits below don't fix that (only the `local_api` backend removes the
        socket entirely), but they take away the cheap escalations: no new
        privileges, no capabilities, a memory ceiling instead of an OOM on the
        host, a pid ceiling instead of a fork bomb.

        `network_disabled` is passed only where the tool genuinely has nothing to
        fetch: Grype needs its vulnerability database and syft needs the registry
        or daemon, but gitleaks, checkov and a directory SBOM never do.
        """
        return {
            "network_disabled": not network,
            "mem_limit": SCAN_MEMORY_LIMIT,
            "pids_limit": SCAN_PIDS_LIMIT,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges"],
        }

    def _run_container(
        self,
        image: str,
        command: list,
        volumes: Dict[str, Dict[str, str]],
        label: str,
        network: bool = False,
    ):
        """Runs `image` to completion and returns `(stdout, stderr, exit_code)`
        with the two streams kept apart.

        `containers.run()` can only hand back one combined log, and every
        JSON-parsing caller here needs stdout clean — so passing
        `stderr=True` there would corrupt the payload, which is why stderr
        used to be dropped with `stderr=False`. Creating the container
        ourselves lets us read each stream separately: stdout stays
        parseable *and* the tool's own explanation survives into
        `Scan.error` (see `ScannerExecutionError`).
        """
        client = self._docker_client()
        container = client.containers.create(
            image=image, command=command, volumes=volumes, **self._hardening(network)
        )
        try:
            container.start()
            try:
                exit_code = (container.wait(timeout=self.timeout_seconds) or {}).get("StatusCode", 0)
            except requests.exceptions.RequestException as e:
                # docker-py implements `wait` as an HTTP request against the
                # daemon, so a timeout surfaces as a requests read timeout
                # rather than a docker-specific error. Anything else from the
                # same family (daemon gone, socket refused) is not a timeout, so
                # it is re-raised untouched.
                if not _is_timeout(e):
                    raise
                logger.warning("%s exceeded %ss — killing the container", label, self.timeout_seconds)
                try:
                    container.kill()
                except Exception:
                    logger.warning("Could not kill timed-out %s container", image, exc_info=True)
                raise ScannerTimeoutError(
                    label, self.timeout_seconds, container.logs(stdout=False, stderr=True)
                ) from e
            stdout = container.logs(stdout=True, stderr=False)
            stderr = container.logs(stdout=False, stderr=True)
        finally:
            # `remove=True` on run() used to handle this; do it by hand now,
            # and never let a cleanup failure mask the real scan error.
            try:
                container.remove(force=True)
            except Exception:
                logger.warning("Could not remove %s container after %s", image, label, exc_info=True)
        if stderr:
            # Full, untruncated output — `Scan.error` only gets a 180-char digest.
            logger.info("%s stderr: %s", label, stderr.decode("utf-8", errors="replace").strip())
        return stdout, stderr, exit_code

    def _run_container_json(
        self,
        image: str,
        command: list,
        volumes: Dict[str, Dict[str, str]],
        label: str,
        network: bool = False,
    ) -> Any:
        """`_run_container` plus JSON decoding, raising `ScannerExecutionError`
        (stderr attached) on either a non-zero exit or unparseable stdout."""
        stdout, stderr, exit_code = self._run_container(image, command, volumes, label, network)
        if exit_code != 0:
            raise ScannerExecutionError(label, exit_code, stderr, stdout)
        try:
            return json.loads(stdout.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ScannerExecutionError(label, exit_code, stderr, stdout) from e

    def generate_sbom_for_image(self, image_string: str) -> Dict[str, Any]:
        # `docker:`, not `registry:` — syft's own registry client truncates
        # cross-platform layer downloads ("unable to populate layer cache
        # ... unexpected EOF"), which made every container scan fail on an
        # arm64 host auditing a linux/amd64 image. Going through the
        # Docker daemon (whose puller handles this correctly) fixes it, and
        # reuses any locally cached image instead of refetching every scan.
        # syft still pulls via the daemon when the image isn't local yet.
        #
        # --platform stays mandatory: without it the daemon hands back the
        # *host* architecture, silently producing an SBOM for a variant
        # nobody asked to audit.
        return self._run_container_json(
            self.SYFT_IMAGE,
            ["docker:" + image_string, "--platform", self.image_scan_platform, "-o", "json"],
            self._docker_socket_volumes(),
            f"syft (SBOM de l'image {image_string})",
            # Pulls through the daemon, and may reach the registry.
            network=True,
        )

    def generate_sbom_for_directory(self, work_dir: str, sub_path: str) -> Dict[str, Any]:
        target = f"/src/{sub_path}" if sub_path else "/src"
        return self._run_container_json(
            self.SYFT_IMAGE,
            ["dir:" + target, "-o", "json"],
            {os.path.abspath(work_dir): {"bind": "/src", "mode": "ro"}},
            "syft (SBOM du répertoire)",
        )

    def scan_sbom(self, work_dir: str, sbom: Dict[str, Any]) -> Dict[str, Any]:
        sbom_file_path = os.path.join(work_dir, "sbom.json")
        with open(sbom_file_path, "w") as f:
            json.dump(sbom, f)

        return self._run_container_json(
            self.GRYPE_IMAGE,
            ["sbom:/work/sbom.json", "-o", "json"],
            {os.path.abspath(work_dir): {"bind": "/work", "mode": "ro"}},
            "grype (analyse du SBOM)",
            # Downloads/refreshes its vulnerability database.
            network=True,
        )

    def scan_secrets(self, work_dir: str, sub_path: str = "") -> list:
        source = f"/repo/{sub_path}" if sub_path else "/repo"

        # --no-git: treat the checkout as plain files rather than replaying
        # git history — repos are cloned with `depth=1`, so history-based
        # scanning would miss almost everything anyway.
        # --exit-code=0: gitleaks exits 1 by default when it finds secrets;
        # here that's an expected outcome, not a failed container run, so
        # results are read from the report file instead of the exit code.
        # Any *other* non-zero exit is a real failure and still raises.
        # The report is written to the *workspace root* (`/repo`), not into
        # the scanned target (`/repo/{sub_path}`) — it has to live inside the
        # mounted volume for the container to write it at all, and it holds
        # every detected secret in cleartext, so it must stay out of the tree
        # the rest of the pipeline walks (see SOURCE_SUBDIR in
        # zanshin/services/scan_processor.py).
        label = "gitleaks (recherche de secrets)"
        _, stderr, exit_code = self._run_container(
            self.GITLEAKS_IMAGE,
            [
                "detect",
                f"--source={source}",
                "--no-git",
                "--report-format=json",
                f"--report-path=/repo/{self.GITLEAKS_REPORT_FILENAME}",
                "--exit-code=0",
            ],
            {os.path.abspath(work_dir): {"bind": "/repo", "mode": "rw"}},
            label,
        )
        if exit_code != 0:
            raise ScannerExecutionError(label, exit_code, stderr)

        report_path = os.path.join(work_dir, self.GITLEAKS_REPORT_FILENAME)
        if not os.path.exists(report_path):
            return []
        with open(report_path) as f:
            content = f.read().strip()
        return json.loads(content) if content else []

    def scan_iac(self, work_dir: str, sub_path: str = "") -> Optional[list]:
        target = f"/repo/{sub_path}" if sub_path else "/repo"

        # --soft-fail: checkov exits 1 by default when it finds failed
        # checks — same reasoning as gitleaks's --exit-code=0, a finding is
        # an expected outcome here, not a failed container run.
        try:
            payload = self._run_container_json(
                self.CHECKOV_IMAGE,
                ["-d", target, "-o", "json", "--soft-fail", "--compact"],
                {os.path.abspath(work_dir): {"bind": "/repo", "mode": "ro"}},
                "checkov (analyse IaC)",
            )
        except Exception:
            # checkov's exact CLI/output behavior varies across versions and
            # detected frameworks, so a failure here must not sink the whole scan.
            #
            # It returns `None`, not `[]`, and that changed: `[]` means "analysed,
            # clean", which `ScanIngestor` reads as licence to resolve every IaC issue
            # the target has. A checkov crash would therefore have declared a repository
            # fixed. `None` says nothing was looked at, and the backlog is left alone.
            logger.exception("checkov IaC scan failed or returned unparsable output — skipping")
            return None

        # checkov returns a single report object when one framework (e.g.
        # terraform) is detected, or a list of report objects when several
        # are (terraform + kubernetes in the same repo, for instance).
        reports = payload if isinstance(payload, list) else [payload]
        failed_checks = []
        for report in reports:
            failed_checks.extend((report.get("results") or {}).get("failed_checks", []))
        return failed_checks

    def scan_sast(
        self, work_dir: str, sub_path: str = "", rules_sub_path: str = ""
    ) -> Optional[list]:
        """Run Semgrep over the checkout with the rules the runner placed in the workspace.

        Several details here were established against the real image rather than assumed,
        and each of them is load-bearing:

        - **`semgrep` heads the command.** The image has no entrypoint (its `Cmd` is
          `["semgrep", "--help"]`), unlike `bridgecrew/checkov` — copying the shape of
          `scan_iac` would produce a nonsense command line and exit 2.
        - **`--no-rewrite-rule-ids`.** With `--config` pointing at a *directory*, Semgrep
          prefixes every `check_id` with the rule file's relative path. Reorganising the
          rule tree would therefore rename every identifier — and the identifier is part
          of an issue's fingerprint, so every SAST finding would resolve and reappear as
          new, losing its triage.
        - **No `--error`.** `semgrep scan` exits 0 when it finds something (it is
          `semgrep ci` that exits 1), so there is no `--soft-fail` equivalent to pass and
          any non-zero code is a genuine failure. `_run_container_json` already treats it
          that way.
        - **Network disabled**, like gitleaks and checkov: the rules are on disk, and
          `--metrics=off` / `--disable-version-check` stop Semgrep from spending its
          startup in a DNS timeout trying to reach semgrep.dev.
        - **`--max-memory` sits below `SCAN_MEMORY_LIMIT`**, so a large repository
          degrades through Semgrep's own limiter rather than being OOM-killed at 137.
        """
        target = f"/repo/{sub_path}" if sub_path else "/repo"
        rules = f"/repo/{rules_sub_path}" if rules_sub_path else "/repo"
        label = "semgrep (analyse du code source)"

        try:
            payload = self._run_container_json(
                self.SEMGREP_IMAGE,
                [
                    "semgrep", "scan",
                    f"--config={rules}",
                    "--no-rewrite-rule-ids",
                    "--json",
                    "--metrics=off",
                    "--disable-version-check",
                    "--quiet",
                    "--timeout=30",
                    "--timeout-threshold=3",
                    "--max-target-bytes=1000000",
                    "--max-memory=1500",
                    "--jobs=2",
                    target,
                ],
                {os.path.abspath(work_dir): {"bind": "/repo", "mode": "ro"}},
                label,
            )
        except Exception:
            # `None`, not `[]` — see `scan_iac` above and `ScannerEngine.scan_sast`.
            # This catch also covers `ScannerTimeoutError`, which is raised from
            # `container.wait` rather than from parsing: Semgrep is the first scanner for
            # which the global timeout is a plausible normal outcome on a large
            # repository, and a timed-out run knows nothing about the code.
            logger.exception("semgrep SAST scan failed or returned unparsable output — skipping")
            return None

        # A rule that fails to load is reported in `errors` while the run still exits 0.
        # One malformed file aborts everything (`code 7`, nothing scanned), which would
        # otherwise read as a clean repository.
        errors = payload.get("errors") or []
        scanned = (payload.get("paths") or {}).get("scanned") or []
        if not scanned:
            logger.error("semgrep scanned no file at all (%d error(s)) — treating as not run", len(errors))
            return None
        if errors and len(errors) > self.SEMGREP_MAX_ERROR_RATIO * len(scanned):
            logger.error(
                "semgrep reported %d error(s) over %d scanned file(s) — treating as not run",
                len(errors), len(scanned),
            )
            return None
        if errors:
            logger.warning("semgrep reported %d non-fatal error(s)", len(errors))

        # Paths come back container-side (`/repo/source/app/main.py`). They are rewritten
        # here, in the one place that knows what `/repo` was mounted from, so that every
        # backend hands the ingestor the same repository-relative path — and because the
        # path is part of an issue's fingerprint, which must not depend on where the scan
        # happened to run.
        results = payload.get("results") or []
        for result in results:
            result["path"] = _strip_prefix(result.get("path"), target)
        return results

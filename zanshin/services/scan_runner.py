"""Execution of a scan: clone, run the scanners, return the raw output.

The half of the old `ScanProcessor` that touches a disk, a git remote and a
`ScannerEngine` — and nothing else. No database session, no `Scan` row, no
encryption key, no settings lookup: it takes a `ScanTask` and returns
`ScanArtifacts`.

That is not tidiness, it is the enabling constraint for agents (décision 0003):
a remote agent has a Docker socket and a temp directory but no access to the
control plane's database, so the only code it can possibly run is code shaped
like this. `ScanProcessor` composes this class with `ScanIngestor` for local
execution, and `zanshin/agent/worker.py` runs it on another machine — the same
steps, in the same order, either way.
"""
import logging
import os
import shutil
import tempfile
import time
from typing import Callable, Optional

import git

from zanshin.scan_contract import ScanArtifacts, ScanTask
from zanshin.services.git_url import validate_repo_url
from zanshin.services.scanners.base import ScannerEngine

logger = logging.getLogger(__name__)

# Extensions considered "source code" for the optional AI review sample
# (§4bis, docs/TECHNICAL_DOCUMENTATION.md) — deliberately broad rather than
# exhaustive; this is a lightweight complement to the dedicated scanners,
# not a language-aware pipeline.
AI_REVIEW_TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".c", ".h", ".cpp", ".hpp", ".cs", ".rs", ".kt", ".swift",
    ".yml", ".yaml", ".json", ".tf", ".sql", ".sh",
}
AI_REVIEW_EXCLUDED_DIRS = {".git", "node_modules", ".venv", "__pycache__", "dist", "build"}
# Sub-directory of the per-scan workspace that holds *only* the scan target
# (the git checkout). Every artifact Zanshin's own pipeline writes —
# `sbom.json` for Grype, gitleaks' JSON report — lands in the workspace root,
# i.e. deliberately *outside* this directory.
#
# The separation is structural rather than a filename blocklist because two
# of those artifacts are actively harmful to feed back into the pipeline:
# gitleaks' report contains every detected secret in cleartext (it would have
# been sent to the AI review model), and a Syft SBOM routinely exceeds
# AI_REVIEW_MAX_CHARS on its own (it would have consumed the entire review
# budget before the first source file, so the model reviewed the SBOM instead
# of the code). Keeping the target in its own directory means anything
# walking the source tree can never reach them, whatever gets added later.
SOURCE_SUBDIR = "source"
# Sibling of SOURCE_SUBDIR holding the Semgrep rule tree for the duration of the scan.
#
# Copying rules into the workspace looks like a detour — they already exist on disk next
# to this module — but it is the only placement that works everywhere. Volume paths are
# resolved by the *Docker daemon*, not by the process calling it: when Zanshin itself
# runs in a container with the socket mounted, a directory inside Zanshin's image is
# invisible to the sibling Semgrep container. The workspace is the one path both sides
# already agree on, because every other scanner is handed files through it.
#
# It sits outside SOURCE_SUBDIR for the same reason `sbom.json` and the gitleaks report
# do: nothing that walks the scanned tree — the AI review sample above all — must be able
# to reach Zanshin's own files.
RULES_SUBDIR = "rules"
# Where the shipped rules live. `zanshin/services/scanners/rules/semgrep/`, resolved
# relative to this file so it works from a checkout, an installed package and the agent
# image alike.
BUILTIN_SEMGREP_RULES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "scanners", "rules", "semgrep"
)
# Optional second rule tree, provided by the operator. Zanshin ships only its own rules:
# the upstream Semgrep registry rules are licensed in a way that forbids redistributing
# them, so anyone wanting that breadth installs it here themselves
# (`scripts/fetch_semgrep_rules.py`). Read from the environment rather than the database
# because a remote agent has neither.
OPERATOR_SEMGREP_RULES_ENV_VAR = "ZANSHIN_SEMGREP_RULES_DIR"
# Size cap for the source sample sent to the model: no chunking/RAG, just a
# straightforward "read files in order until the budget is used up" — good
# enough for the "minimal review" this feature is scoped to, but it means
# large repositories are silently truncated rather than reviewed in full.
AI_REVIEW_MAX_CHARS = 40000

class ScanRunner:
    """Runs one `ScanTask` and returns its `ScanArtifacts`.

    Stateless and reusable: `run()` creates its own workspace and removes it
    before returning, whatever happened. Exceptions propagate — deciding what a
    failure means to a `Scan` row is the caller's business, and the caller
    differs (locally `ScanProcessor`, remotely the agent worker reporting a
    failed result).
    """

    def __init__(self, scanner_engine: ScannerEngine):
        # `scanner_engine` decides *where* the tools actually run (local Docker
        # containers, a sidecar HTTP service, or OSV.dev for the matching step —
        # see docs/architecture/). This class only orders the steps; it never talks to
        # Docker directly, which is also why an agent can pick a different
        # engine than the control plane would have used.
        self.scanner_engine = scanner_engine

    def run(
        self,
        task: ScanTask,
        on_step: Optional[Callable[[str], None]] = None,
    ) -> ScanArtifacts:
        """Execute `task`.

        `on_step` is called with a human-readable message before each step. A
        remote agent uses it to stream progress back while the work is still
        running — which is also what renews its lease, so a long scan is not
        mistaken for a dead agent. Every message is accumulated in
        `ScanArtifacts.log` regardless, so a local run keeps the same trace.
        """
        artifacts = ScanArtifacts()

        def step(message: str) -> None:
            artifacts.log.append(message)
            logger.info(message)
            if on_step:
                try:
                    on_step(message)
                except Exception:
                    # Progress reporting is not the work. An agent whose
                    # heartbeat fails should keep scanning and let the lease
                    # decide, not abort a scan that is running fine.
                    logger.exception("Progress callback failed — continuing the scan")

        start_time = time.time()
        temp_dir = self._make_workspace(task)
        try:
            if task.is_container:
                step(f"Génération du SBOM de l'image {task.image}")
                artifacts.sbom = self.scanner_engine.generate_sbom_for_image(task.image)

                step("Analyse du SBOM (vulnérabilités connues)")
                artifacts.cves = self.scanner_engine.scan_sbom(temp_dir, artifacts.sbom)
            else:
                validate_sub_path(task.sub_path)

                # The checkout goes in its own sub-directory so that the
                # artifacts the steps below write into the workspace root
                # (sbom.json, gitleaks' report) stay out of the scanned tree —
                # see SOURCE_SUBDIR. Everything handed to the engine is
                # therefore addressed relative to the workspace root, prefixed
                # with that sub-directory.
                source_dir = os.path.join(temp_dir, SOURCE_SUBDIR)
                scan_target = (
                    os.path.join(SOURCE_SUBDIR, task.sub_path) if task.sub_path else SOURCE_SUBDIR
                )

                step(f"Clonage de {task.repo_url} (branche {task.branch})")
                clone_repo(task.repo_url, task.branch, source_dir, task.ssh_private_key)

                step(f"Génération du SBOM du répertoire (cible : {task.sub_path or '.'})")
                artifacts.sbom = self.scanner_engine.generate_sbom_for_directory(temp_dir, scan_target)

                step("Analyse du SBOM (vulnérabilités connues)")
                artifacts.cves = self.scanner_engine.scan_sbom(temp_dir, artifacts.sbom)

                # Source-code-only steps: not run for container images, see
                # docs/architecture/01.
                step("Recherche de secrets codés en dur")
                artifacts.secrets = self.scanner_engine.scan_secrets(temp_dir, scan_target)

                step("Analyse des manifestes Infrastructure-as-Code")
                artifacts.iac = self.scanner_engine.scan_iac(temp_dir, scan_target)

                if task.run_sast:
                    rules_sub_path = self._stage_semgrep_rules(temp_dir)
                    if rules_sub_path is None:
                        # No rule at all would make Semgrep exit non-zero, and a "SAST
                        # found nothing" result from a run with no rules would resolve
                        # the target's whole SAST backlog. Leaving `artifacts.sast` at
                        # `None` says the analysis did not happen.
                        step("Analyse du code source ignorée : aucune règle Semgrep disponible")
                    else:
                        step("Analyse du code source (motifs vulnérables et de qualité)")
                        artifacts.sast = self.scanner_engine.scan_sast(
                            temp_dir, scan_target, rules_sub_path
                        )

                if task.collect_code_sample:
                    # `source_dir`, not `temp_dir`: the review must only ever
                    # see the checkout, never the pipeline's own artifacts (see
                    # SOURCE_SUBDIR).
                    step("Collecte de l'échantillon de code pour la revue IA")
                    artifacts.code_sample = collect_ai_review_sample(source_dir, task.sub_path)

            artifacts.duration_ms = int((time.time() - start_time) * 1000)
            return artifacts
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _stage_semgrep_rules(self, temp_dir: str) -> Optional[str]:
        """Copy the rule trees into the workspace; return their path relative to it.

        Two sources, merged into one directory: the rules Zanshin ships, and whatever the
        operator installed (see `OPERATOR_SEMGREP_RULES_ENV_VAR`). They land in separate
        sub-directories so a rule id collision between the two is visible as two files
        rather than one silently overwriting the other.

        Returns `None` when neither source yields a single rule file — the caller must
        not run Semgrep with an empty config, since "no rules, no findings" is
        indistinguishable from "clean code" once it reaches the ingestor.
        """
        destination = os.path.join(temp_dir, RULES_SUBDIR)
        sources = [("builtin", BUILTIN_SEMGREP_RULES_DIR)]
        operator_dir = (os.getenv(OPERATOR_SEMGREP_RULES_ENV_VAR) or "").strip()
        if operator_dir:
            sources.append(("operator", operator_dir))

        staged = 0
        for name, source in sources:
            if not os.path.isdir(source):
                logger.warning("Semgrep rule directory %s does not exist: %s", name, source)
                continue
            target = os.path.join(destination, name)
            shutil.copytree(source, target, dirs_exist_ok=True)
            staged += sum(
                1
                for _, _, files in os.walk(target)
                for filename in files
                if filename.endswith((".yaml", ".yml"))
            )

        if not staged:
            logger.error("No Semgrep rule file found — skipping the SAST step")
            return None
        logger.info("Staged %d Semgrep rule file(s) for this scan", staged)
        return RULES_SUBDIR

    def _make_workspace(self, task: ScanTask) -> str:
        # `get_workspace_root()` returns None for every backend except
        # LocalApiScannerEngine, which needs the workspace created inside the
        # volume it shares with its sidecar service instead of the OS default
        # temp location (see docs/architecture/01).
        workspace_root = self.scanner_engine.get_workspace_root()
        if workspace_root:
            os.makedirs(workspace_root, exist_ok=True)
        return tempfile.mkdtemp(prefix=f"zanshin_scan_{task.scan_id}_", dir=workspace_root)

def validate_sub_path(path: str) -> None:
    if path and (".." in path or path.startswith("/") or "\\" in path):
        raise ValueError("Chemin invalide : la traversée de répertoire n'est pas autorisée.")

def clone_repo(
    repo_url: str,
    branch: str,
    work_dir: str,
    ssh_private_key: Optional[str] = None,
) -> None:
    """Shallow-clone `repo_url` into `work_dir`.

    Takes key *material* rather than a key id: there is no key store to look an
    id up in here, and on an agent there could not be one (décision 0003). The
    control plane resolves the id and decides whether to include the material at
    all — a `local`-mode agent gets none and relies on the credentials its own
    machine already has.
    """
    # Re-validated here and not only at save time: this is the single choke
    # point every scan goes through, including for repository rows that predate
    # the validation (see zanshin/services/git_url.py for why an unchecked URL
    # is an RCE, not just a bad input).
    repo_url = validate_repo_url(repo_url)
    env = {}
    key_file_path = None
    try:
        if ssh_private_key:
            # Temporary key file with strict permissions, removed below. The
            # material never lands anywhere else — on the control plane or on an
            # agent.
            fd, key_file_path = tempfile.mkstemp()
            os.close(fd)
            with open(key_file_path, "w") as f:
                f.write(ssh_private_key)
            os.chmod(key_file_path, 0o600)
            env["GIT_SSH_COMMAND"] = f"ssh -i {key_file_path} -o StrictHostKeyChecking=no -o BatchMode=yes"
        else:
            # No key supplied: git falls back to whatever the machine running
            # this already has (`~/.ssh`, an ssh-agent, a credential helper).
            # That is the whole point of a `local`-mode agent — see décision 0003.
            env["GIT_SSH_COMMAND"] = "ssh -o StrictHostKeyChecking=no -o BatchMode=yes"

        git.Repo.clone_from(
            url=repo_url,
            to_path=work_dir,
            branch=branch,
            depth=1,
            env=env,
        )
    finally:
        if key_file_path and os.path.exists(key_file_path):
            os.remove(key_file_path)

def collect_ai_review_sample(source_dir: str, sub_path: str) -> str:
    """Best-effort, size-capped concatenation of source files for the optional
    AI review (see `AI_REVIEW_MAX_CHARS`) — deliberately simple (no chunking, no
    embeddings/RAG): walks the tree in sorted order and stops once the character
    budget is used up, so large repositories are silently truncated rather than
    exhaustively reviewed. Adequate for the "minimal review" this feature is
    scoped to (see docs/architecture/01), not a substitute for a real SAST pipeline.

    `source_dir` is the checkout itself (`SOURCE_SUBDIR`), never the workspace
    root — that's what keeps the pipeline's own artifacts out of the sample, and
    it also makes the `# <path>` headers below repository-relative, which is the
    only form the model can usefully echo back in `file_path`.
    """
    root = os.path.join(source_dir, sub_path) if sub_path else source_dir
    chunks = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in AI_REVIEW_EXCLUDED_DIRS)
        for filename in sorted(filenames):
            if not any(filename.endswith(ext) for ext in AI_REVIEW_TEXT_EXTENSIONS):
                continue
            file_path = os.path.join(dirpath, filename)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            rel_path = os.path.relpath(file_path, source_dir)
            chunk = f"# {rel_path}\n{content}\n"
            if total + len(chunk) > AI_REVIEW_MAX_CHARS:
                remaining = AI_REVIEW_MAX_CHARS - total
                if remaining > 0:
                    chunks.append(chunk[:remaining])
                return "\n".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
    return "\n".join(chunks)

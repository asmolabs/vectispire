"""Tests for ScanRunner — the half of the pipeline that runs the scanners.

Two things are being pinned down here. The obvious one is that the steps still
happen in the right order for each kind of target. The load-bearing one is that
this module stays **runnable without the control plane**: an agent has no
database, no encryption key and no settings table, so a test that proves the
import graph is clean is testing the feature, not the code style (décision 0003).
"""
import os
import subprocess
import sys
import textwrap

import pytest

import zanshin.services.scan_runner as scan_runner_module
from zanshin.scan_contract import TARGET_CONTAINER, TARGET_REPOSITORY, ScanTask
from zanshin.services.scan_runner import (
    AI_REVIEW_MAX_CHARS,
    SOURCE_SUBDIR,
    ScanRunner,
    collect_ai_review_sample,
    validate_sub_path,
)


class FakeScannerEngine:
    """Records the workspace-relative target it was handed for each step, which
    is what the `SOURCE_SUBDIR` assertions below need."""

    def __init__(self, sbom=None, cves=None, secrets=None, iac=None, sast=None, raise_on=None):
        self.sbom = sbom if sbom is not None else {"artifacts": []}
        self.cves = cves if cves is not None else {"matches": []}
        self.secrets = secrets if secrets is not None else []
        self.iac = iac if iac is not None else []
        self.sast = sast if sast is not None else []
        self.raise_on = raise_on
        self.calls = []
        self.workspaces = []
        # What the runner staged, captured while the workspace still exists — it is
        # removed before `run()` returns.
        self.staged_rules = None

    def scan_sast(self, work_dir, sub_path="", rules_sub_path=""):
        self.calls.append(("scan_sast", sub_path, rules_sub_path))
        self.workspaces.append(work_dir)
        rules_dir = os.path.join(work_dir, rules_sub_path)
        self.staged_rules = sorted(
            os.path.relpath(os.path.join(root, name), rules_dir)
            for root, _, files in os.walk(rules_dir)
            for name in files
            if name.endswith((".yaml", ".yml"))
        )
        if self.raise_on == "scan_sast":
            raise RuntimeError("boom")
        return self.sast

    def get_workspace_root(self):
        return None

    def generate_sbom_for_image(self, image_string):
        self.calls.append(("generate_sbom_for_image", image_string))
        if self.raise_on == "generate_sbom_for_image":
            raise RuntimeError("boom")
        return self.sbom

    def generate_sbom_for_directory(self, work_dir, sub_path):
        self.calls.append(("generate_sbom_for_directory", sub_path))
        self.workspaces.append(work_dir)
        if self.raise_on == "generate_sbom_for_directory":
            raise RuntimeError("boom")
        return self.sbom

    def scan_sbom(self, work_dir, sbom):
        self.calls.append(("scan_sbom",))
        self.workspaces.append(work_dir)
        if self.raise_on == "scan_sbom":
            raise RuntimeError("boom")
        return self.cves

    def scan_secrets(self, work_dir, sub_path=""):
        self.calls.append(("scan_secrets", sub_path))
        return self.secrets

    def scan_iac(self, work_dir, sub_path=""):
        self.calls.append(("scan_iac", sub_path))
        return self.iac


@pytest.fixture(autouse=True)
def patch_git_clone(monkeypatch):
    """No real git remote in tests: create the destination and leave one source
    file behind, like a shallow clone would."""

    def fake_clone_from(url, to_path, branch, depth, env):
        os.makedirs(to_path, exist_ok=True)
        with open(os.path.join(to_path, "app.py"), "w") as f:
            f.write("import os\nAPI_KEY = 'hardcoded-secret'\n")

    monkeypatch.setattr(scan_runner_module.git.Repo, "clone_from", fake_clone_from)


def repo_task(**overrides):
    task = {
        "scan_id": 1,
        "kind": TARGET_REPOSITORY,
        "repo_url": "https://example.com/org/repo.git",
        "branch": "main",
        "sub_path": "",
    }
    task.update(overrides)
    return ScanTask(**task)


# --- Step ordering ------------------------------------------------------------

def test_repository_scan_runs_every_step_and_returns_raw_output():
    engine = FakeScannerEngine(
        cves={"matches": [{"vulnerability": {"id": "CVE-1", "severity": "high"}}]},
        secrets=[{"RuleID": "aws-key", "File": "app.py"}],
        iac=[{"check_id": "CKV_1"}],
    )

    artifacts = ScanRunner(engine).run(repo_task())

    assert [c[0] for c in engine.calls] == [
        "generate_sbom_for_directory", "scan_sbom", "scan_secrets", "scan_iac",
    ]
    assert artifacts.cves["matches"][0]["vulnerability"]["id"] == "CVE-1"
    assert artifacts.secrets[0]["RuleID"] == "aws-key"
    assert artifacts.iac[0]["check_id"] == "CKV_1"
    # Recorded so a slow scan can be told apart from a stuck one.
    assert artifacts.duration_ms >= 0


def test_container_scan_skips_the_source_code_only_steps():
    engine = FakeScannerEngine()

    artifacts = ScanRunner(engine).run(
        ScanTask(scan_id=2, kind=TARGET_CONTAINER, image="ghcr.io/org/app:1.2")
    )

    assert [c[0] for c in engine.calls] == ["generate_sbom_for_image", "scan_sbom"]
    # No checkout exists for an image, so secrets/IaC/SAST would have nothing to read
    # (docs/architecture/01). IaC and SAST report `None` — "not analysed" — rather than an
    # empty list, which would claim the image was analysed and found clean.
    assert artifacts.secrets == []
    assert artifacts.iac is None
    assert artifacts.sast is None
    assert engine.calls[0][1] == "ghcr.io/org/app:1.2"


def test_the_scanned_target_is_the_source_subdirectory_never_the_workspace_root():
    """The checkout is addressed through `SOURCE_SUBDIR` so the pipeline's own
    artifacts (sbom.json, the gitleaks report) can never be inside the tree the
    scanners walk."""
    engine = FakeScannerEngine()

    ScanRunner(engine).run(repo_task(sub_path="services/api"))

    # `scan_sbom` records no target (it is handed the SBOM, not a path).
    targets = dict(call for call in engine.calls if len(call) == 2)
    assert targets["generate_sbom_for_directory"] == os.path.join(SOURCE_SUBDIR, "services/api")
    assert targets["scan_secrets"] == os.path.join(SOURCE_SUBDIR, "services/api")
    assert targets["scan_iac"] == os.path.join(SOURCE_SUBDIR, "services/api")


def test_workspace_is_removed_even_when_a_step_raises():
    engine = FakeScannerEngine(raise_on="scan_sbom")
    runner = ScanRunner(engine)

    with pytest.raises(RuntimeError):
        runner.run(repo_task())

    # The engine recorded the workspace it was given; nothing must survive.
    assert engine.workspaces
    for workspace in engine.workspaces:
        assert not os.path.exists(workspace)


def test_failures_propagate_rather_than_being_swallowed():
    """What a failure *means* is the caller's decision: locally it fails a `Scan`
    row, remotely it becomes a reported failed result."""
    with pytest.raises(RuntimeError, match="boom"):
        ScanRunner(FakeScannerEngine(raise_on="generate_sbom_for_directory")).run(repo_task())


# --- Progress reporting -------------------------------------------------------

def test_on_step_is_called_for_every_step_and_also_recorded_in_the_log():
    engine = FakeScannerEngine()
    seen = []

    artifacts = ScanRunner(engine).run(repo_task(), on_step=seen.append)

    assert len(seen) >= 4
    assert seen == artifacts.log
    assert any("Clonage" in line for line in seen)


def test_a_failing_progress_callback_does_not_fail_the_scan():
    """An agent whose heartbeat request fails must keep scanning: the lease, not
    the callback, decides whether the work is still alive."""

    def exploding(_message):
        raise ConnectionError("controller unreachable")

    artifacts = ScanRunner(FakeScannerEngine()).run(repo_task(), on_step=exploding)

    assert artifacts.log  # steps still recorded
    assert artifacts.duration_ms >= 0


# --- Code sample --------------------------------------------------------------

def test_code_sample_is_only_collected_when_the_task_asks_for_it():
    engine = FakeScannerEngine()

    without = ScanRunner(engine).run(repo_task(collect_code_sample=False))
    with_sample = ScanRunner(engine).run(repo_task(collect_code_sample=True))

    assert without.code_sample == ""
    assert "app.py" in with_sample.code_sample


def test_collect_ai_review_sample_filters_by_extension_and_excludes_dirs(tmp_path):
    (tmp_path / "app.py").write_text("print('hello')")
    (tmp_path / "README.md").write_text("# not source code, excluded by extension")
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "lib.js").write_text("should not be read")

    sample = collect_ai_review_sample(str(tmp_path), "")

    assert "app.py" in sample and "print('hello')" in sample
    assert "README.md" not in sample
    assert "should not be read" not in sample


def test_collect_ai_review_sample_truncates_at_max_chars(tmp_path):
    (tmp_path / "big.py").write_text("x" * (AI_REVIEW_MAX_CHARS * 2))

    sample = collect_ai_review_sample(str(tmp_path), "")

    assert len(sample) <= AI_REVIEW_MAX_CHARS + len("# big.py\n")


# --- Path validation ----------------------------------------------------------

def test_validate_sub_path_rejects_traversal():
    for bad in ("../etc/passwd", "/etc/passwd", "sub\\path"):
        with pytest.raises(ValueError):
            validate_sub_path(bad)


def test_validate_sub_path_accepts_normal_relative_paths():
    validate_sub_path("")
    validate_sub_path("services/api")


# --- The property that makes a remote agent possible --------------------------

def test_scan_runner_and_the_contract_import_no_database_or_ui_code():
    """A runner that could import `zanshin.database` would eventually be given a
    session, and the "agents need no database" guarantee of décision 0003 would
    quietly stop being true. Checked in a fresh interpreter because anything the
    rest of this test session imported would otherwise already be in
    `sys.modules`.
    """
    program = textwrap.dedent(
        """
        import sys
        import zanshin.scan_contract  # noqa: F401
        import zanshin.services.scan_runner  # noqa: F401

        forbidden = [
            name for name in sys.modules
            if name.startswith(("zanshin.database", "zanshin.models", "zanshin.ui", "reflex"))
            or name == "sqlalchemy"
        ]
        print(",".join(sorted(forbidden)))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "", f"scan_runner pulled in: {result.stdout.strip()}"


# --- Semgrep rules in the workspace -------------------------------------------
#
# Copying the rule tree into each scan's workspace looks like a detour, since the rules
# already exist on disk next to the package. It is not: volume paths are resolved by the
# Docker *daemon*, so a directory that lives inside Zanshin's own container image is
# invisible to the sibling Semgrep container. The workspace is the one path both sides
# already agree on.

def test_the_step_is_skipped_unless_the_task_asks_for_it():
    engine = FakeScannerEngine()

    ScanRunner(engine).run(repo_task())

    assert "scan_sast" not in [c[0] for c in engine.calls]


def test_the_rules_are_staged_in_the_workspace_and_handed_over_by_relative_path():
    engine = FakeScannerEngine()

    ScanRunner(engine).run(repo_task(run_sast=True))

    call = next(c for c in engine.calls if c[0] == "scan_sast")
    assert call[2] == scan_runner_module.RULES_SUBDIR
    # Zanshin's own rules arrived, under their own sub-directory.
    assert engine.staged_rules
    assert all(path.startswith("builtin" + os.sep) for path in engine.staged_rules)


def test_the_rules_live_outside_the_scanned_tree():
    """Same invariant as `sbom.json` and the gitleaks report: nothing walking the source
    tree — the AI review sample above all — may reach Zanshin's own files."""
    engine = FakeScannerEngine()

    ScanRunner(engine).run(repo_task(run_sast=True))

    call = next(c for c in engine.calls if c[0] == "scan_sast")
    scanned_target, rules_path = call[1], call[2]
    assert not rules_path.startswith(scanned_target)
    assert not scanned_target.startswith(rules_path)


def test_an_operator_rule_directory_is_merged_in(tmp_path, monkeypatch):
    """The rules Zanshin ships are its own; the upstream sets are not redistributable,
    so an operator installs them separately and points at them here."""
    operator_rules = tmp_path / "operator-rules"
    operator_rules.mkdir()
    (operator_rules / "extra.yaml").write_text("rules: []\n")
    monkeypatch.setenv(scan_runner_module.OPERATOR_SEMGREP_RULES_ENV_VAR, str(operator_rules))
    engine = FakeScannerEngine()

    ScanRunner(engine).run(repo_task(run_sast=True))

    assert any(path.startswith("operator" + os.sep) for path in engine.staged_rules)
    # Kept in separate sub-directories so a rule id present in both shows up as two
    # files rather than one silently overwriting the other.
    assert any(path.startswith("builtin" + os.sep) for path in engine.staged_rules)


def test_no_rules_means_the_step_does_not_run_at_all(monkeypatch, tmp_path):
    """Semgrep with an empty config finds nothing, and "found nothing" would resolve the
    target's whole SAST backlog. Not running is the only safe answer."""
    monkeypatch.setattr(scan_runner_module, "BUILTIN_SEMGREP_RULES_DIR", str(tmp_path / "absent"))
    monkeypatch.delenv(scan_runner_module.OPERATOR_SEMGREP_RULES_ENV_VAR, raising=False)
    engine = FakeScannerEngine()

    artifacts = ScanRunner(engine).run(repo_task(run_sast=True))

    assert "scan_sast" not in [c[0] for c in engine.calls]
    assert artifacts.sast is None

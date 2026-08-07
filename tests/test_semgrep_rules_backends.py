"""Zanshin's own Semgrep rules, run against real fixtures by the real engine.

Two failures this closes, both of which would otherwise be discovered by users:

- **A rule that stops matching.** Semgrep's pattern syntax is not stable across the
  constructs it supports, and two of the rules written here parsed as YAML, loaded
  without complaint, and matched nothing until the pattern was rewritten. A ruleset that
  silently matches nothing looks exactly like a clean codebase.
- **A rule that starts matching its near miss.** Every fixture pairs a genuine hit with
  the case that must stay silent — the literal command, the safe loader, the hash
  declared as non-security, `== null`. Those exclusions are what keep the ruleset usable;
  a scanner that cries wolf is a scanner people turn off.

One malformed rule file also aborts the *entire* run (`code 7`, zero files scanned), so
this suite doubles as the check that the shipped directory loads at all.

The expectation lives next to the code it describes: a line carrying
`zanshin: <rule-id>` must be reported by that rule, and any line without a marker must
not be reported at all. Run with `pytest -m backends`.
"""
import collections
import json
import os
import re
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.backends

RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "zanshin", "services", "scanners", "rules", "semgrep",
)
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "semgrep_fixtures")

MARKER = re.compile(r"zanshin:\s*(?P<rule>[a-z0-9-]+)")


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except Exception:
        return False


if not _docker_available():
    pytest.skip("Docker is not available", allow_module_level=True)


def _expected_from_markers():
    """`{(file, line): {rule_id, ...}}` read from the fixtures themselves."""
    expected = collections.defaultdict(set)
    for root, _, files in os.walk(FIXTURES_DIR):
        for name in files:
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as handle:
                for number, text in enumerate(handle, start=1):
                    for match in MARKER.finditer(text):
                        expected[(name, number)].add(match.group("rule"))
    return expected


@pytest.fixture(scope="module")
def semgrep_payload():
    """The engine's raw JSON, produced once for the whole module."""
    from zanshin.services.scanners.docker_engine import DockerScannerEngine

    completed = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{RULES_DIR}:/rules:ro",
            "-v", f"{FIXTURES_DIR}:/src:ro",
            DockerScannerEngine.SEMGREP_IMAGE,
            "semgrep", "scan", "--config=/rules", "--no-rewrite-rule-ids",
            "--json", "--metrics=off", "--disable-version-check", "--quiet", "/src",
        ],
        capture_output=True,
        timeout=600,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")[-2000:]
    payload = json.loads(completed.stdout.decode("utf-8"))

    # A rule that fails to parse is reported here rather than raising: semgrep loads what
    # it can and carries on, so an unusable rule would otherwise pass as "found nothing".
    assert payload.get("errors") == [], json.dumps(payload["errors"], indent=1)
    assert payload.get("paths", {}).get("scanned"), "no fixture file was scanned"

    return payload


@pytest.fixture(scope="module")
def reported(semgrep_payload):
    """`{(file, line): {rule_id, ...}}` as the real engine reports it."""
    found = collections.defaultdict(set)
    for result in semgrep_payload["results"]:
        found[(os.path.basename(result["path"]), result["start"]["line"])].add(result["check_id"])
    return dict(found)


def test_every_shipped_rule_matches_its_fixture(reported):
    """Each rule in the directory must fire at least once. A rule nobody exercises is a
    rule nobody knows is broken."""
    shipped = set()
    for root, _, files in os.walk(RULES_DIR):
        for name in files:
            if not name.endswith((".yaml", ".yml")):
                continue
            with open(os.path.join(root, name), encoding="utf-8") as handle:
                shipped.update(re.findall(r"^\s*-?\s*id:\s*([a-z0-9-]+)", handle.read(), re.M))

    fired = {rule for rules in reported.values() for rule in rules}

    assert shipped, "no rules found in the shipped directory"
    assert shipped - fired == set(), f"règles qui ne matchent plus rien : {sorted(shipped - fired)}"


def test_the_marked_lines_are_the_reported_lines(reported):
    expected = _expected_from_markers()

    missing = {key: rules - reported.get(key, set()) for key, rules in expected.items()}
    missing = {key: rules for key, rules in missing.items() if rules}

    assert missing == {}, f"attendu mais non signalé : {missing}"


def test_the_unmarked_lines_stay_silent(reported):
    """The half that keeps the ruleset usable: every near miss must produce nothing."""
    expected = _expected_from_markers()

    spurious = {key: rules - expected.get(key, set()) for key, rules in reported.items()}
    spurious = {key: rules for key, rules in spurious.items() if rules}

    assert spurious == {}, f"faux positifs : {spurious}"


def test_security_and_quality_are_separated_by_category(semgrep_payload):
    """The metadata field that routes a finding to `sast` or `quality`.

    A rule filed under the wrong one lands in the wrong backlog, and the asymmetry
    matters: a `security` rule mistakenly categorised as quality silently loses the
    ability to fail a gate, which is a security regression that nothing else would catch.

    Checked against the engine's own reading of the metadata rather than a YAML parse of
    the files, so it verifies what Semgrep will actually report — and so this suite needs
    no YAML dependency it would otherwise be the only user of.
    """
    from zanshin.services.sast_service import (
        FINDING_TYPE_QUALITY,
        FINDING_TYPE_SAST,
        SEVERITY_BY_SEMGREP_LEVEL,
        SastService,
    )

    by_rule = {}
    for result in semgrep_payload["results"]:
        extra = result.get("extra") or {}
        by_rule[result["check_id"]] = extra

    # Which file each rule came from, taken from the shipped tree.
    origin = {}
    for root, _, files in os.walk(RULES_DIR):
        for name in files:
            if not name.endswith((".yaml", ".yml")):
                continue
            with open(os.path.join(root, name), encoding="utf-8") as handle:
                for rule_id in re.findall(r"^\s*-?\s*id:\s*([a-z0-9-]+)", handle.read(), re.M):
                    origin[rule_id] = name

    for rule_id, extra in by_rule.items():
        metadata = extra.get("metadata") or {}
        assert metadata.get("category"), f"{rule_id} n'a pas de metadata.category"
        assert extra.get("severity") in SEVERITY_BY_SEMGREP_LEVEL, (
            f"{rule_id} a une sévérité hors du vocabulaire semgrep : {extra.get('severity')}"
        )

        expected_type = (
            FINDING_TYPE_SAST
            if origin[rule_id].startswith("security")
            else FINDING_TYPE_QUALITY
        )
        assert SastService.finding_type_of(metadata) == expected_type, (
            f"{rule_id} est dans {origin[rule_id]} mais se classe en "
            f"{SastService.finding_type_of(metadata)}"
        )

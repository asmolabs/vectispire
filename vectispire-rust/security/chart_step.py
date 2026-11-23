#!/usr/bin/env python3
"""Runs one step of CI's `helm-chart` job, by its name, on this machine: the step's own script, read from
`.github/workflows/ci.yml`, in the chart's directory, with `helm` from the image `kubernetes-scan-check.sh` pins.

For the mutation checks of the chart (`security/mutants/agent-known-hosts.py`): a rendering check kept only in the
workflow can be proved against a broken template here rather than by pushing one. Docker is needed; nothing is
installed. The chart is copied into the container, so a step writing its renderings beside the chart leaves the
tree as it was.

    security/chart_step.py "the pinned host keys are mounted, not copied"
"""
import os
import re
import subprocess
import sys

import yaml

REPOSITORY = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKFLOW = os.path.join(REPOSITORY, ".github", "workflows", "ci.yml")
CHECK = os.path.join(REPOSITORY, "scripts", "kubernetes-scan-check.sh")


def helm_image():
    with open(CHECK, encoding="utf-8") as f:
        found = re.search(r"^HELM_IMAGE=(\S+)$", f.read(), re.MULTILINE)
    if not found:
        sys.exit(f"no HELM_IMAGE= in {CHECK}")
    return found.group(1)


def step(name):
    with open(WORKFLOW, encoding="utf-8") as f:
        steps = yaml.safe_load(f)["jobs"]["helm-chart"]["steps"]
    matching = [s for s in steps if s.get("name") == name]
    if len(matching) != 1:
        sys.exit(f"{len(matching)} steps of helm-chart are named {name!r}")
    if matching[0].get("working-directory") != "deploy/helm/vectispire":
        sys.exit(f"{name!r} does not run in the chart's directory")
    return matching[0]["run"]


def main(args):
    if len(args) != 1:
        sys.exit(__doc__)
    script = "set -e\ncp -r /source /chart\ncd /chart\n" + step(args[0])
    chart = os.path.join(REPOSITORY, "deploy", "helm", "vectispire")
    return subprocess.run(["docker", "run", "--rm", "-i", "--network", "none", "-v", f"{chart}:/source:ro",
                           "--entrypoint", "sh", helm_image(), "-c", script]).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

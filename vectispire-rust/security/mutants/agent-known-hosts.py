#!/usr/bin/env python3
"""Mutation check of the chart's pinned host keys for either agent's image (branch rust/agent-known-hosts, 2026-11-23):
`agents.knownHosts` mounted read-only where the agent reads it, on a home volume of the pod's own, with no init
container. Each mutant must turn CI's `helm-chart` step red. See README.md.

The guard is a template, so the test is a command of its own (`--exec`): `security/chart_step.py` runs the step from
`.github/workflows/ci.yml` with the pinned `helm`, in Docker, a few seconds each. What a missed guard costs: a pin the
agent can write is a list it learns new hosts into (accept-new instead of the operator's pin), and a home the runtime
creates as root fails every keyed clone of the Java agent (JGit's configuration) — both invisible until a scan.
"""
import sys

import _runner

D = "../deploy/helm/vectispire/templates/agents/deployment.yaml"
T = ["--exec", sys.executable, "security/chart_step.py", "the pinned host keys are mounted, not copied"]

MUTANTS = [
    ("the pin mounted writable", D,
     "              subPath: known_hosts\n              readOnly: true\n", "              subPath: known_hosts\n", T),
    ("the pin's mode writable", D, "            defaultMode: 0444\n", "", T),
    ("the home left to the runtime", D,
     "            - name: home\n              mountPath: {{ $work }}/home\n", "", T,
     [("        - name: home\n          emptyDir:\n            sizeLimit: 16Mi\n", "")]),
    ("the whole ConfigMap mounted as .ssh", D,
     "              mountPath: {{ $work }}/home/.ssh/known_hosts\n              subPath: known_hosts\n",
     "              mountPath: {{ $work }}/home/.ssh\n", T),
    ("the home and the pin rendered without host keys", D,
     "            {{- if .Values.agents.knownHosts }}\n            # **Mounted where",
     "            {{- if true }}\n            # **Mounted where", T),
    ("the copy back, with a shell", D, "      containers:\n        - name: agent\n",
     "      initContainers:\n        - name: known-hosts\n          image: x\n          command:\n            - sh\n"
     "      containers:\n        - name: agent\n", T),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=180, description=__doc__))

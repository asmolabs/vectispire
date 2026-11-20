#!/usr/bin/env python3
"""Mutation check of the agent image's notices (branch rust/agent-compose-dropin, 2026-11-20): which crates'
licences `security/third-party-licences.py` ships in /app/THIRD-PARTY-LICENSES, and its checks of NOTICE and
LICENSE. Each mutant must turn `security/third_party_licences_test.py` red. See README.md.

The guards are Python, so the test is a command of its own (`--exec`), not `cargo test`; no Docker, a few seconds
each. What a missed guard costs is an image distributed without an attribution its licence requires — invisible to
every scan and every run, which is why each is pinned.
"""
import sys

import _runner

S = "security/third-party-licences.py"
T = ["--exec", sys.executable, "security/third_party_licences_test.py"]

MUTANTS = [
    # Which crates are linked.
    ("normal dependencies not followed", S, 'if None in kinds or ("build" in kinds and name in BUNDLED):',
     'if "build" in kinds and name in BUNDLED:', T),
    ("every build dependency shipped", S, 'if None in kinds or ("build" in kinds and name in BUNDLED):',
     'if None in kinds or "build" in kinds:', T),
    ("the bundled build dependency left out", S, 'if None in kinds or ("build" in kinds and name in BUNDLED):',
     "if None in kinds:", T),
    ("the workspace's own crates listed", S, 'return [packages[i] for i in seen if packages[i]["source"] is not None]',
     "return [packages[i] for i in seen]", T),
    ("one platform only", S, "    for meta in metas:\n", "    for meta in metas[:1]:\n", T),
    # What each crate ships.
    ("COPYING and NOTICE files not read", S, 'r"(?i)^(licen[cs]e|copying|notice|copyright|unlicense)([-_.].*)?$"',
     'r"(?i)^(licen[cs]e)([-_.].*)?$"', T),
    ("line ends kept", S, '.replace("\\r\\n", "\\n").rstrip()', ".rstrip()", T),
    ("a bundled licence that moved passes", S, "            if not os.path.isfile(path):\n",
     "            if False:\n", T),
    ("the bundled library's licence not copied", S,
     '            files.append((f"{relative} — {library}, bundled and linked: {bundled_licence}", read(path)))\n',
     "", T),
    # NOTICE and LICENSE.
    ("any LICENSE accepted", S, "    if licence != root_licence:\n", "    if False:\n", T),
    ("a copyright line extended accepted", S, 'if not notice.startswith(root_head + "\\n"):',
     "if not notice.startswith(root_head):", T),
    ("a licence named inside a longer one accepted", S,
     'if not re.search(r"(?<![A-Za-z0-9.\\-])" + re.escape(identifier) + r"(?![A-Za-z0-9\\-]|\\.[0-9])", notice):',
     "if identifier not in notice:", T),
    ("bundled libraries need not be named", S, "        named.add(library)\n", "        pass\n", T),
    # Staleness.
    ("a stale list passes", S, 'raw(OUTPUT).decode("utf-8") != rendered', "False", T),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=120, description=__doc__))

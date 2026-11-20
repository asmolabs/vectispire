#!/usr/bin/env python3
"""Two agents' answers to the same composition, compared — the side-by-side conformance of the Rust agent.

Usage: compare-agent-runs.py <reference dir> <candidate dir> <accepted differences file>

Each directory is what `composition-scan-check.sh` keeps under `DETAIL_DIR` for one agent: per scan, the
scan's detail (`<label>.scan.json`) and its target's issues after it (`<label>.issues.json`). The reference is
the Java agent, which ships; the candidate is the Rust one.

**What is compared is what the control plane recorded, not what the agents said.** The scan's status, its
failed steps and their sentences, whether it carries an SBOM, the types it examined — `null` (never recorded)
and `[]` (examined nothing) are two answers, as an absent step and an empty one are (decision 0007) —, its
plugins' outcomes, every finding, and every issue with its **fingerprint**: a fingerprint that differs is an
issue resolved and recreated on the day the image is swapped, its triage lost (AGENTS.md).

**What differs between any two runs is set aside, and only that**: database ids, instants and durations. An
instant's presence is kept (`notBefore` set or not is a fate of the queue), and so is every other field: a
field the comparison cannot explain is a difference, never noise to filter.

A difference is accepted only by a line of the accepted-differences file, with its reason; a line that no
difference used fails the run too, so the list only shrinks.
"""
import fnmatch
import json
import re
import sys
from pathlib import Path

INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
# Database ids and the run's clock: what two runs of the same thing never share.
# `slaDays` is counted from now to a due date, and moves with the clock between the two runs.
VOLATILE = {"id", "repoId", "containerId", "targetId", "scanId", "firstSeenScanId", "lastSeenScanId",
            "durationMs", "resolutionSeconds", "slaDays"}
# A list whose order the comparison does not read, keyed by what makes an element itself.
KEYS = {
    "findings": lambda f: " ".join(str(f.get(k)) for k in ("type", "identifier", "packageName", "packageVersion",
                                                            "filePath", "line")),
    "plugins": lambda p: str(p.get("pluginId", p.get("id"))),
    "issues": lambda i: str(i.get("fingerprint")),
}


def normalise(value):
    if isinstance(value, dict):
        return {k: normalise(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return [normalise(v) for v in value]
    if isinstance(value, str):
        return INSTANT.sub("<instant>", value)
    return value


def as_keyed(name, items):
    key = KEYS.get(name)
    if key is None or not all(isinstance(i, dict) for i in items):
        return None
    keyed = {}
    for item in items:
        k = key(item)
        while k in keyed:  # two elements alike in every keyed field: numbered, in order
            k += "+"
        keyed[k] = item
    return keyed


def diff(path, a, b, out):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in list(a) + [k for k in b if k not in a]:
            if k not in a:
                out.append((f"{path}.{k}", "absent", b[k]))
            elif k not in b:
                out.append((f"{path}.{k}", a[k], "absent"))
            else:
                diff(f"{path}.{k}", a[k], b[k], out)
        return
    if isinstance(a, list) and isinstance(b, list):
        name = path.rsplit(".", 1)[-1]
        ka, kb = as_keyed(name, a), as_keyed(name, b)
        if ka is not None and kb is not None:
            for k in list(ka) + [k for k in kb if k not in ka]:
                if k not in ka:
                    out.append((f"{path}[{k}]", "absent", kb[k]))
                elif k not in kb:
                    out.append((f"{path}[{k}]", ka[k], "absent"))
                else:
                    diff(f"{path}[{k}]", ka[k], kb[k], out)
            return
        if len(a) == len(b):
            for i, (x, y) in enumerate(zip(a, b)):
                diff(f"{path}[{i}]", x, y, out)
            return
    if a != b:
        out.append((path, a, b))


def load(directory, name):
    path = directory / name
    return normalise(json.loads(path.read_text())) if path.exists() else "absent"


def issues(document):
    # The route answers a page or a list, as the API has it; the comparison wants the issues.
    if isinstance(document, dict):
        for k in ("issues", "content", "items"):
            if isinstance(document.get(k), list):
                return document[k]
    return document


def accepted_lines(path):
    lines = []
    for number, raw in enumerate(Path(path).read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(" | ")]
        if len(parts) != 3 or not all(parts):
            sys.exit(f"{path}:{number}: expected '<scan> | <field path> | <reason>', got: {raw}")
        lines.append((number, parts[0], parts[1], parts[2]))
    return lines


def short(value):
    text = json.dumps(value, sort_keys=True) if not isinstance(value, str) else value
    return text if len(text) <= 300 else text[:300] + "…"


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__.split("\n\n")[1])
    reference, candidate = Path(sys.argv[1]), Path(sys.argv[2])
    accepted = accepted_lines(sys.argv[3])
    labels = sorted({p.name.split(".")[0] for d in (reference, candidate) for p in d.glob("*.json")})
    if not labels:
        sys.exit("✗ neither run kept anything: there is nothing to compare")
    differences = []
    for label in labels:
        found = []
        diff("scan", load(reference, f"{label}.scan.json"), load(candidate, f"{label}.scan.json"), found)
        diff("issues", issues(load(reference, f"{label}.issues.json")),
             issues(load(candidate, f"{label}.issues.json")), found)
        differences += [(label, *d) for d in found]

    used, refused = set(), []
    for label, path, a, b in differences:
        match = next((n for n, scan, pattern, _ in accepted
                      if fnmatch.fnmatchcase(label, scan) and fnmatch.fnmatchcase(path, pattern)), None)
        if match is None:
            refused.append((label, path, a, b))
        else:
            used.add(match)
            print(f"  accepted (line {match}): {label} {path}")
    print(f"scans compared: {', '.join(labels)}")
    for label, path, a, b in refused:
        print(f"✗ {label} {path}\n    reference: {short(a)}\n    candidate: {short(b)}")
    stale = [(n, scan, pattern) for n, scan, pattern, _ in accepted if n not in used]
    for n, scan, pattern in stale:
        print(f"✗ accepted difference on line {n} ({scan} | {pattern}) was not seen: remove it — the list only shrinks")
    if refused or stale:
        print(f"{len(refused)} difference(s) not accepted, {len(stale)} accepted line(s) unused")
        sys.exit(1)
    print(f"identical, {len(used)} accepted line(s) used")


if __name__ == "__main__":
    main()

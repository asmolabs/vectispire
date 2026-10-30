#!/usr/bin/env python3
"""Writes the result bodies the load scenario's agents hand back: one per seeded target.

Each is the next round of what `seed.py` sent for that target — the same generator, one drift further
— so a scan finishing during the load run resolves a few issues and opens a few, as a real rescan
does, rather than replacing a target's whole backlog. Read by k6 into a shared array.
"""
import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import seed  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed-file", default="load/.state/seed.json")
    ap.add_argument("--out", default="load/.state/bodies.json")
    args = ap.parse_args()
    state = json.load(open(args.seed_file))
    cfg = argparse.Namespace(**state["parameters"])
    pool = seed.package_pool(random.Random(cfg.seed), cfg.packages)
    steps = ("DEPENDENCIES", "SECRETS", "IAC", "SAST")
    bodies = [{"match": t["match"], "body": json.dumps(seed.scan_artifacts(t, pool, cfg.rounds, cfg, steps))}
              for t in state["targets"]]
    with open(args.out, "w") as f:
        json.dump(bodies, f)
    print("%d bodies, %.0f MB, written to %s" % (len(bodies), os.path.getsize(args.out) / 1e6, args.out))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Samples the control plane's pool, heap, GC and CPU through Actuator while a level runs.

Actuator's metrics answer an administrator's session only (`ActuatorAccess`), so this signs in as the
seeded administrator. Writes one CSV line per period and, on SIGTERM/SIGINT, a summary JSON: the peak
and mean of each gauge, and what the GC did over the run.
"""
import argparse
import csv
import json
import signal
import sys
import time
import urllib.request

GAUGES = [
    ("pool_active", "hikaricp.connections.active", None),
    ("pool_pending", "hikaricp.connections.pending", None),
    ("pool_idle", "hikaricp.connections.idle", None),
    ("pool_max", "hikaricp.connections.max", None),
    ("heap_used_mb", "jvm.memory.used", "area:heap"),
    ("heap_max_mb", "jvm.memory.max", "area:heap"),
    ("cpu_process", "process.cpu.usage", None),
    ("threads_live", "jvm.threads.live", None),
]
COUNTERS = [
    ("gc_pause_count", "jvm.gc.pause", "COUNT"),
    ("gc_pause_total_s", "jvm.gc.pause", "TOTAL_TIME"),
    ("pool_timeouts", "hikaricp.connections.timeout", "COUNT"),
    ("pool_acquire_count", "hikaricp.connections.acquire", "COUNT"),
    ("pool_acquire_total_s", "hikaricp.connections.acquire", "TOTAL_TIME"),
]


def fetch(base, token, name, tag=None):
    url = "%s/actuator/metrics/%s%s" % (base, name, ("?tag=" + tag) if tag else "")
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)
    except Exception:
        return None


def stat(doc, statistic="VALUE"):
    if not doc:
        return None
    for m in doc.get("measurements", []):
        if m["statistic"] == statistic:
            return m["value"]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--summary", required=True)
    ap.add_argument("--period", type=float, default=2.0)
    args = ap.parse_args()

    body = json.dumps({"username": args.user, "password": args.password}).encode()
    req = urllib.request.Request(args.base + "/api/v1/auth/login", data=body, headers={"Content-Type": "application/json"})
    token = json.load(urllib.request.urlopen(req))["token"]

    def counters():
        return {k: stat(fetch(args.base, token, n), s) for k, n, s in COUNTERS}

    start = counters()
    rows = []
    stop = {"now": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(now=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(now=True))
    with open(args.csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t"] + [g[0] for g in GAUGES])
        t0 = time.time()
        while not stop["now"]:
            row = {}
            for key, name, tag in GAUGES:
                v = stat(fetch(args.base, token, name, tag))
                if v is not None and key.endswith("_mb"):
                    v = v / 1048576
                row[key] = v
            rows.append(row)
            w.writerow([round(time.time() - t0, 1)] + [None if row[g[0]] is None else round(row[g[0]], 3) for g in GAUGES])
            f.flush()
            time.sleep(args.period)
    end = counters()
    summary = {}
    for key, _, _ in GAUGES:
        vals = [r[key] for r in rows if r.get(key) is not None]
        if vals:
            summary[key] = {"max": round(max(vals), 3), "mean": round(sum(vals) / len(vals), 3)}
    for key in start:
        if start[key] is not None and end[key] is not None:
            summary[key + "_delta"] = round(end[key] - start[key], 3)
    if summary.get("pool_acquire_count_delta"):
        summary["pool_acquire_mean_ms"] = round(
            1000 * summary.get("pool_acquire_total_s_delta", 0) / summary["pool_acquire_count_delta"], 3)
    json.dump(summary, open(args.summary, "w"), indent=1)


if __name__ == "__main__":
    sys.exit(main())

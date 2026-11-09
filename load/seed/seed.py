#!/usr/bin/env python3
"""Seeds a control plane with an estate shaped like a production one, through its own API.

Everything goes through the routes a person, a pipeline or an agent calls — accounts, teams, grants,
targets, scans, triage — and the scans' results arrive through the agent protocol: a declared agent
claims each queued scan (``GET /api/v1/agent/jobs``) and hands back a synthetic ``ScanArtifacts``
document (``POST /api/v1/agent/jobs/{id}/result``) carrying a Syft SBOM and the findings of every
analyser. So the issues, their fingerprints, the inventory rows, the licence findings and the scan
history are written by the ingestion code that writes them in production, not by an INSERT. No row
is written by SQL.

Every name is invented. The data is deterministic for a given ``--seed``.

Standard library only (Python 3.9+), so the harness needs nothing installed beyond Docker and a JDK.
"""
import argparse
import http.client
import json
import random
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# --------------------------------------------------------------------------------------------------
# HTTP


class Api:
    """One keep-alive connection per thread; JSON in, JSON out, and a failure is an exception."""

    def __init__(self, base, token=None):
        self.base = urllib.parse.urlparse(base)
        self.token = token
        self.local = threading.local()

    def _conn(self):
        conn = getattr(self.local, "conn", None)
        if conn is None:
            conn = http.client.HTTPConnection(self.base.hostname, self.base.port, timeout=300)
            self.local.conn = conn
        return conn

    def call(self, method, path, body=None, token=None, raw=None, expect=(200, 201, 204), headers=None):
        hdrs = {"Accept": "application/json"}
        tok = token or self.token
        if tok:
            hdrs["Authorization"] = "Bearer " + tok
        data = None
        if raw is not None:
            data = raw
            hdrs["Content-Type"] = "application/json"
        elif body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        for attempt in range(3):
            conn = self._conn()
            try:
                conn.request(method, path, body=data, headers=hdrs)
                resp = conn.getresponse()
                payload = resp.read()
                break
            except (http.client.HTTPException, ConnectionError, TimeoutError):
                conn.close()
                self.local.conn = None
                if attempt == 2:
                    raise
        if resp.status not in expect:
            raise RuntimeError("%s %s -> %d %s" % (method, path, resp.status, payload[:400].decode(errors="replace")))
        if not payload:
            return None
        try:
            return json.loads(payload)
        except ValueError:
            return payload


def items(answer, key=None):
    """A list route answers an array, or an object carrying one."""
    if isinstance(answer, dict):
        return answer.get(key) or answer.get("items") or []
    return answer or []


def list_all(api, path, token, key=None):
    """Every element of a paged list route (500 at most a page)."""
    out, offset = [], 0
    while True:
        page = items(api.call("GET", "%s?limit=500&offset=%d" % (path, offset), token=token), key)
        out += page
        if len(page) < 500:
            return out
        offset += 500


def sign_in(api, username, password):
    answer = api.call("POST", "/api/v1/auth/login", {"username": username, "password": password})
    return answer["token"], answer["user"]


# --------------------------------------------------------------------------------------------------
# The synthetic estate

ECOSYSTEMS = [
    # (purl type, syft type, language, share)
    ("npm", "npm", "javascript", 0.35),
    ("maven", "java-archive", "java", 0.25),
    ("pypi", "python", "python", 0.15),
    ("golang", "go-module", "go", 0.10),
    ("deb", "deb", "", 0.15),
]
LICENSES = (["MIT"] * 40 + ["Apache-2.0"] * 25 + ["BSD-3-Clause"] * 10 + ["ISC"] * 6 + ["BSD-2-Clause"] * 4
            + ["MPL-2.0"] * 3 + ["LGPL-2.1-only"] * 3 + ["EPL-2.0"] * 2 + ["GPL-3.0-only"] * 2 + ["GPL-2.0-only"]
            + ["AGPL-3.0-only"] + ["UNLICENSED"] + [None] * 2)
SYLLABLES = ["ar", "bel", "cor", "dax", "el", "fin", "gor", "hal", "ix", "jun", "kel", "lum", "mor", "nex",
             "or", "pax", "qui", "ras", "sol", "tur", "ul", "vex", "wix", "yar", "zen"]
SEVERITIES = ["CRITICAL"] * 4 + ["HIGH"] * 18 + ["MEDIUM"] * 40 + ["LOW"] * 30 + ["UNKNOWN"] * 8
SAST_RULES = [
    ("java.lang.security.audit.sqli.jdbc-sqli", "A03", "HIGH"),
    ("javascript.express.security.audit.xss.direct-response-write", "A03", "MEDIUM"),
    ("python.lang.security.audit.subprocess-shell-true", "A03", "HIGH"),
    ("java.lang.security.audit.crypto.weak-hash", "A02", "MEDIUM"),
    ("go.lang.security.audit.net.bind_all", "A05", "LOW"),
    ("javascript.jsonwebtoken.security.jwt-none-alg", "A07", "HIGH"),
    ("java.spring.security.audit.spring-csrf-disabled", "A01", "MEDIUM"),
    ("python.django.security.audit.unvalidated-password", "A07", "LOW"),
    ("javascript.lang.security.audit.path-traversal", "A01", "HIGH"),
    ("java.lang.security.audit.xxe.documentbuilderfactory", "A05", "HIGH"),
    ("python.requests.security.disabled-cert-validation", "A02", "MEDIUM"),
    ("go.lang.security.audit.crypto.math_random", "A02", "LOW"),
]
IAC_CHECKS = [("CKV_DOCKER_2", "Ensure that HEALTHCHECK instructions have been added"),
              ("CKV_DOCKER_3", "Ensure that a user for the container has been created"),
              ("CKV_K8S_8", "Liveness Probe Should be Configured"),
              ("CKV_K8S_20", "Containers should not run with allowPrivilegeEscalation"),
              ("CKV_K8S_37", "Minimize the admission of containers with capabilities assigned"),
              ("CKV_AWS_20", "S3 Bucket has an ACL defined which allows public READ access"),
              ("CKV_GHA_7", "The build output cannot be affected by user parameters")]
SECRET_RULES = ["generic-api-key", "aws-access-token", "private-key", "slack-webhook-url", "github-pat"]


def word(rng, parts=2):
    return "".join(rng.choice(SYLLABLES) for _ in range(parts))


def package_pool(rng, size):
    """Distinct packages, each with a few versions — shared across targets, as real estates share them."""
    pool = []
    weights = [e[3] for e in ECOSYSTEMS]
    for i in range(size):
        eco = rng.choices(ECOSYSTEMS, weights)[0]
        name = word(rng, rng.randint(2, 3)) + ("-" + word(rng, 1) if rng.random() < 0.4 else "")
        if eco[0] == "maven":
            name = "org.%s:%s" % (word(rng, 1), name)
        elif eco[0] == "golang":
            name = "github.com/%s/%s" % (word(rng, 2), name)
        versions = ["%d.%d.%d" % (rng.randint(0, 9), rng.randint(0, 30), rng.randint(0, 20)) for _ in range(rng.randint(1, 4))]
        pool.append({"eco": eco, "name": name + str(i % 7 if i % 7 else ""), "versions": versions,
                     "license": rng.choice(LICENSES)})
    return pool


def purl_of(pkg, version):
    eco = pkg["eco"][0]
    name = pkg["name"]
    if eco == "maven":
        group, artifact = name.split(":", 1)
        return "pkg:maven/%s/%s@%s" % (group, artifact, version)
    if eco == "deb":
        return "pkg:deb/debian/%s@%s?distro=debian-12" % (name, version)
    return "pkg:%s/%s@%s" % (eco, name, version)


def artifacts_for(target, pool, rng, count, drift):
    """The target's components: a stable core plus a drifting share, so a rescan changes some."""
    base = random.Random(target["seed"])
    chosen = base.sample(range(len(pool)), min(count, len(pool)))
    if drift:
        keep = int(len(chosen) * (1 - drift))
        chosen = chosen[:keep] + rng.sample(range(len(pool)), len(chosen) - keep)
    out = []
    for idx in chosen:
        pkg = pool[idx]
        version = pkg["versions"][base.randrange(len(pkg["versions"]))]
        out.append((idx, pkg, version))
    return out


def scan_artifacts(target, pool, round_no, cfg, steps=("DEPENDENCIES", "SECRETS", "IAC", "SAST")):
    """A ScanArtifacts document as an agent would hand it back."""
    rng = random.Random("%s/%d" % (target["seed"], round_no))
    is_image = target["kind"] == "container"
    count = cfg.components_image if is_image else cfg.components_repo
    drift = 0.0 if round_no == 0 else cfg.drift
    comps = artifacts_for(target, pool, rng, count, drift)

    artifacts, relationships = [], []
    for n, (idx, pkg, version) in enumerate(comps):
        aid = "a%x-%d" % (idx, n)
        lic = pkg["license"]
        artifacts.append({
            "id": aid, "name": pkg["name"], "version": version, "type": pkg["eco"][1],
            "purl": purl_of(pkg, version), "language": pkg["eco"][2],
            "licenses": [] if lic is None else [{"value": lic, "spdxExpression": lic, "type": "declared"}],
            "locations": [{"path": "/app/%s" % ("package-lock.json" if pkg["eco"][0] == "npm" else "lib")}],
        })
        # About a third declared directly, the rest dragged in: the graph decides `only_direct`.
        if n % 3 and n > 0:
            relationships.append({"parent": aid, "child": "a%x-%d" % (comps[n - 1][0], n - 1), "type": "dependency-of"})
    sbom = {"artifacts": artifacts, "artifactRelationships": relationships,
            "source": {"type": "image" if is_image else "directory", "name": target["name"]},
            "descriptor": {"name": "syft", "version": "1.33.0"},
            "schema": {"version": "16.0.34", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.34.json"}}
    if is_image:
        sbom["distro"] = {"id": "debian", "versionID": "12", "name": "Debian GNU/Linux"}

    # Each finding is drawn from a generator of its own, so a drifted one leaves the others where they
    # were: most persist from round to round (same fingerprint, so the same issue), a share is fixed and
    # replaced by a new one — which is what resolves issues and opens others, as a real estate does.
    def item_rng(section, i):
        if round_no and random.Random("%s/%s/%d/drift%d" % (target["seed"], section, i, round_no)).random() < cfg.drift:
            return random.Random("%s/%s/%d/r%d" % (target["seed"], section, i, round_no))
        return random.Random("%s/%s/%d" % (target["seed"], section, i))

    vulns = []
    for i in range(cfg.vulns_image if is_image else cfg.vulns_repo):
        r = item_rng("v", i)
        idx, pkg, version = comps[r.randrange(len(comps))]
        cve = "CVE-%d-%d" % (r.choice([2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026]), r.randint(1000, 59999))
        fixable = r.random() < 0.6
        vulns.append({"identifier": cve, "severity": r.choice(SEVERITIES), "packageName": pkg["name"],
                      "installedVersion": version, "fixVersions": ("%s.1" % version) if fixable else "",
                      "description": "Synthetic advisory %s in %s" % (cve, pkg["name"]),
                      "referenceUrl": "https://nvd.nist.gov/vuln/detail/%s" % cve,
                      "purl": purl_of(pkg, version)})

    doc = {"sbom": sbom, "dependencies": vulns, "plugins": [], "failures": [], "duration": "PT%dS" % rng.randint(40, 900)}
    if is_image:
        # An image scan runs the cataloguer and the matcher only.
        doc.update({"secrets": None, "iac": None, "sast": None})
        return doc

    doc["languages"] = sorted({pkg["eco"][2] for _, pkg, _ in comps if pkg["eco"][2]})
    sast = []
    for i in range(cfg.sast_repo):
        r = item_rng("s", i)
        rule, owasp, sev = r.choice(SAST_RULES)
        sast.append({"ruleId": rule, "category": "security", "severity": sev, "confidence": "MEDIUM",
                     "file": "src/%s/%s.%s" % (word(r, 1), word(r, 2), r.choice(["java", "ts", "py", "go"])),
                     "line": r.randint(1, 900), "message": "Synthetic finding of %s" % rule, "owaspCategory": owasp})
    # A step the task did not ask for is absent, as the agent reports it (decision 0007).
    doc["sast"] = sast if "SAST" in steps else None
    doc["iac"] = []
    for i in range(cfg.iac_repo):
        r = item_rng("i", i)
        check, name = r.choice(IAC_CHECKS)
        doc["iac"].append({"checkId": check, "checkName": name, "file": "deploy/%s.yaml" % word(r, 2),
                           "line": r.randint(1, 200), "guideline": "https://docs.prismacloud.io/",
                           "resource": "%s.%s" % (word(r, 1), word(r, 1))})
    doc["secrets"] = []
    for i in range(cfg.secrets_repo):
        r = item_rng("k", i)
        rule = r.choice(SECRET_RULES)
        doc["secrets"].append({"rule": rule, "description": "Synthetic %s" % rule,
                               "file": "config/%s.env" % word(r, 2), "line": r.randint(1, 80),
                               "fingerprint": "%x" % r.getrandbits(64)})
    return doc


# --------------------------------------------------------------------------------------------------
# Steps


def log(*args):
    print(time.strftime("%H:%M:%S"), *args, flush=True)


def ensure_governor(api, username, password, new_password):
    try:
        token, user = sign_in(api, username, password)
    except RuntimeError:
        token, user = sign_in(api, username, new_password)
        return token
    if user.get("mustChangePassword"):
        api.call("POST", "/api/v1/auth/change-password",
                 {"current_password": password, "new_password": new_password}, token=token)
        token, _ = sign_in(api, username, new_password)
    return token


PEOPLE = [
    # (username, display name, role) — invented
    ("ada.admin", "Ada Admin", "ADMIN"),
    ("cyril.lead", "Cyril Lead", "CISO"),
    ("selma.champion", "Selma Champion", "SECURITY_CHAMPION"),
    ("aude.auditor", "Aude Auditor", "AUDITOR"),
]
TEAMS = ["Payments", "Platform", "Mobile", "Data", "Identity", "Storefront"]


def create_accounts(api, gov, password, readers):
    users = {}
    existing = {u["username"]: u for u in list_all(api, "/api/v1/users", gov, "users")}
    wanted = list(PEOPLE) + [("reader.%02d" % i, "Reader %02d" % i, "USER") for i in range(readers)]
    for username, display, role in wanted:
        if username in existing:
            users[username] = existing[username]
            continue
        users[username] = api.call("POST", "/api/v1/users", {
            "username": username, "display_name": display, "email": username + "@example.test",
            "password": password, "role": role}, token=gov)
    # A created account owes a password change at its first sign-in: settle it now.
    for username, _, _ in wanted:
        if users[username].get("mustChangePassword"):
            tok, _ = sign_in(api, username, password)
            api.call("POST", "/api/v1/auth/change-password",
                     {"current_password": password, "new_password": password + "!"}, token=tok)
    return users


def create_targets(api, admin, cfg):
    repos = {r["name"]: r for r in list_all(api, "/api/v1/repositories", admin)}
    images = {c["imageName"] + ":" + (c.get("tag") or ""): c for c in list_all(api, "/api/v1/containers", admin)}
    rng = random.Random(cfg.seed)
    n_images = cfg.targets // 3
    n_repos = cfg.targets - n_images
    targets = []

    def repo(i):
        name = "%s-%s-%03d" % (TEAMS[i % len(TEAMS)].lower(), word(random.Random(i), 2), i)
        if name in repos:
            r = repos[name]
        else:
            r = api.call("POST", "/api/v1/repositories", {
                "name": name, "url": "https://git.example.test/%s/%s.git" % (TEAMS[i % len(TEAMS)].lower(), name),
                "branch": "main", "scanManualOnly": True, "tier": rng.choice(["TIER_1_MISSION_CRITICAL", "TIER_2_BUSINESS_OPERATIONAL", "TIER_2_BUSINESS_OPERATIONAL", "TIER_3_INTERNAL"])},
                token=admin)
        return {"kind": "repository", "id": r["id"], "name": name, "team": i % len(TEAMS), "seed": "repo-%d" % i,
                "match": "repository|" + r["url"]}

    def image(i):
        name = "registry.example.test/%s/%s" % (TEAMS[i % len(TEAMS)].lower(), word(random.Random(1000 + i), 2))
        tag = "1.%d.%d" % (i % 9, i)
        if name + ":" + tag in images:
            c = images[name + ":" + tag]
        else:
            c = api.call("POST", "/api/v1/containers", {
                "image_name": name, "tag": tag, "scanManualOnly": True, "tier": "TIER_2_BUSINESS_OPERATIONAL"}, token=admin)
        return {"kind": "container", "id": c["id"], "name": name + ":" + tag, "team": i % len(TEAMS), "seed": "image-%d" % i,
                "match": "image|%s|%s" % (c["imageName"], c.get("tag"))}

    with ThreadPoolExecutor(8) as pool:
        targets += list(pool.map(repo, range(n_repos)))
        targets += list(pool.map(image, range(n_images)))
    return targets


def create_teams(api, admin, users, targets, readers):
    existing = {t["name"]: t for t in list_all(api, "/api/v1/teams", admin)}
    teams = []
    for t, name in enumerate(TEAMS):
        team = existing.get(name) or api.call("POST", "/api/v1/teams", {"name": name, "description": "Synthetic team"}, token=admin)
        members = [users["reader.%02d" % i]["id"] for i in range(readers) if i % len(TEAMS) == t]
        if t == 0:
            members.append(users["selma.champion"]["id"])
        api.call("PUT", "/api/v1/teams/%d/members" % team["id"], members, token=admin)
        grants = [{"kind": x["kind"], "id": x["id"]} for x in targets if x["team"] == t]
        api.call("PUT", "/api/v1/teams/%d/targets" % team["id"], grants, token=admin)
        teams.append({"id": team["id"], "name": name, "targets": len(grants), "members": len(members)})
    return teams


def queue_scans(api, admin, targets):
    def one(t):
        path = "/api/v1/%s/%d/scan" % ("repositories" if t["kind"] == "repository" else "containers", t["id"])
        return api.call("POST", path, token=admin)
    with ThreadPoolExecutor(8) as pool:
        return list(pool.map(one, targets))


def run_agent(api, agent_secret, by_key, pool, round_no, cfg, expected, workers):
    """Claims and answers every queued scan, `workers` at a time, as remote agents would."""
    done = {"n": 0, "bytes": 0, "seconds": 0.0}
    lock = threading.Lock()

    def worker():
        idle = 0
        while True:
            with lock:
                if done["n"] >= expected:
                    return
            claim = api.call("GET", "/api/v1/agent/jobs?wait=2", token=agent_secret, expect=(200, 204))
            if not claim:
                idle += 1
                if idle > 5:
                    return
                continue
            idle = 0
            scan_id = claim.get("scanId") or claim.get("scan_id")
            task = claim.get("task") or {}
            key = target_key_of(task)
            target = by_key[key]
            body = json.dumps(scan_artifacts(target, pool, round_no, cfg, task.get("steps") or ())).encode()
            started = time.time()
            api.call("POST", "/api/v1/agent/jobs/%d/result" % scan_id, raw=body, token=agent_secret)
            with lock:
                done["n"] += 1
                done["bytes"] += len(body)
                done["seconds"] += time.time() - started
                if done["n"] % 25 == 0:
                    log("  round %d: %d/%d results ingested" % (round_no, done["n"], expected))

    with ThreadPoolExecutor(workers) as ex:
        for f in [ex.submit(worker) for _ in range(workers)]:
            f.result()
    return done


def target_key_of(task):
    """A task names its target as an executor needs it — a URL, an image reference — never by id."""
    target = task.get("target") or {}
    if target.get("kind") == "repository":
        return "repository|" + target["url"]
    if target.get("kind") == "image":
        ref = target.get("reference") or {}
        return "image|%s|%s" % (ref.get("imageName"), ref.get("tag"))
    raise RuntimeError("cannot tell the target of task %s" % json.dumps(task)[:300])


def triage(api, tokens, cfg):
    """Decisions by people, in bulk as the issue list offers them, then one by one for a share."""
    lead = tokens["cyril.lead"]
    rng = random.Random(cfg.seed + 7)
    page = api.call("GET", "/api/v1/issues?state=open&limit=1&offset=0", token=lead)
    total = page["total"]
    target = int(total * cfg.triage_share)
    log("triaging %d of %d open issues" % (target, total))
    ids = []
    offset = 0
    while len(ids) < target * 2 and offset < total:
        chunk = api.call("GET", "/api/v1/issues?state=open&limit=500&offset=%d" % offset, token=lead)["items"]
        ids += [i["id"] for i in chunk]
        offset += 500
    rng.shuffle(ids)
    ids = ids[:target]
    decisions = [("AFFECTED", None, None), ("UNDER_REVIEW", None, None),
                 ("NOT_AFFECTED", "vulnerable_code_not_in_execute_path", None),
                 ("WILL_NOT_FIX", None, 90), ("FIXED", None, None)]
    written = 0
    for start in range(0, len(ids), 100):
        batch = ids[start:start + 100]
        status, just, days = decisions[(start // 100) % len(decisions)]
        body = {"ids": batch, "status": status, "comment": "Synthetic decision, batch %d" % (start // 100)}
        if just:
            body["justification"] = just
        if days:
            body["expires_in_days"] = days
        api.call("POST", "/api/v1/issues/triage", body, token=lead)
        written += len(batch)
    # A second decision on a share of them, one by one: issues with more than one entry of history.
    for issue_id in ids[: len(ids) // 5]:
        api.call("POST", "/api/v1/issues/%d/triage" % issue_id,
                 {"status": "AFFECTED", "comment": "Reopened for review"}, token=lead)
        written += 1
    return written


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:3190")
    ap.add_argument("--governor", default="governor")
    ap.add_argument("--governor-password", required=True)
    ap.add_argument("--password", default="Load-test-password-2026", help="every seeded account's (throwaway)")
    ap.add_argument("--targets", type=int, default=300, help="repositories and images, two to one")
    ap.add_argument("--readers", type=int, default=24, help="restricted accounts, spread over the teams")
    ap.add_argument("--rounds", type=int, default=3, help="scans per target; each round after the first drifts")
    ap.add_argument("--drift", type=float, default=0.08, help="share of findings and components changed per round")
    ap.add_argument("--packages", type=int, default=12000, help="distinct packages the estate draws from")
    ap.add_argument("--components-repo", type=int, default=900)
    ap.add_argument("--components-image", type=int, default=1600)
    ap.add_argument("--vulns-repo", type=int, default=90)
    ap.add_argument("--vulns-image", type=int, default=200)
    ap.add_argument("--sast-repo", type=int, default=35)
    ap.add_argument("--iac-repo", type=int, default=12)
    ap.add_argument("--secrets-repo", type=int, default=3)
    ap.add_argument("--triage-share", type=float, default=0.25)
    ap.add_argument("--agent-workers", type=int, default=4)
    ap.add_argument("--seed", type=int, default=20261030)
    ap.add_argument("--out", default="load/.state/seed.json")
    cfg = ap.parse_args()

    started = time.time()
    api = Api(cfg.base)
    gov_password = cfg.governor_password
    gov = ensure_governor(api, cfg.governor, gov_password, gov_password + "!")
    log("governor signed in")

    # Static analysis is a setting, off on a first install; production estates run it.
    # And the licence rule reads a blocklist nobody has written on a first install.
    api.call("PUT", "/api/v1/settings", {"sast_enabled": "true",
                                         "license_blocklist": "GPL-3.0-only,AGPL-3.0-only,UNLICENSED"},
             token=gov)
    users = create_accounts(api, gov, cfg.password, cfg.readers)
    tokens = {u: sign_in(api, u, cfg.password + "!")[0] for u in ("ada.admin", "cyril.lead")}
    admin = tokens["ada.admin"]
    log("%d accounts" % len(users))

    targets = create_targets(api, admin, cfg)
    by_key = {t["match"]: t for t in targets}
    log("%d targets" % len(targets))
    teams = create_teams(api, admin, users, targets, cfg.readers)
    log("%d teams" % len(teams))

    agents = {a["name"]: a for a in list_all(api, "/api/v1/admin/agents", admin)}
    if "load-agent" in agents:
        sys.exit("an agent named load-agent exists already: seed a fresh database (load/env.sh down && up)")
    declared = api.call("POST", "/api/v1/admin/agents", {"name": "load-agent", "description": "Synthetic agent",
                                                          "max_concurrent": 16}, token=admin)
    agent_secret = declared["secret"]
    api.call("POST", "/api/v1/agent/hello", {"contract_version": "1", "hostname": "load-host", "platform": "linux/amd64",
                                             "version": "load", "scanner_engine": "docker", "capabilities": ""},
             token=agent_secret)

    pool = package_pool(random.Random(cfg.seed), cfg.packages)
    timings = []
    for round_no in range(cfg.rounds):
        t0 = time.time()
        queue_scans(api, admin, targets)
        done = run_agent(api, agent_secret, by_key, pool, round_no, cfg, len(targets), cfg.agent_workers)
        timings.append({"round": round_no, "results": done["n"], "seconds": round(time.time() - t0, 1),
                        "mean_result_seconds": round(done["seconds"] / max(done["n"], 1), 2),
                        "mean_result_bytes": done["bytes"] // max(done["n"], 1)})
        log("round %d: %s" % (round_no, timings[-1]))

    triaged = triage(api, tokens, cfg)
    log("%d triage decisions" % triaged)

    # The integration keys a pipeline would hold: one per gated repository, restricted to it.
    gate_keys = []
    for t in [x for x in targets if x["kind"] == "repository"][:10]:
        issued = api.call("POST", "/api/v1/api-keys", {"name": "ci-%s" % t["name"], "scopes": ["scan", "read"],
                                                       "target_kind": "repository", "target_id": t["id"],
                                                       "expires_in_days": 30}, token=admin)
        gate_keys.append({"repository_id": t["id"], "secret": issued["secret"]})

    open_issues = api.call("GET", "/api/v1/issues?state=open&limit=1", token=admin)["total"]
    all_issues = api.call("GET", "/api/v1/issues?limit=1", token=admin)["total"]
    out = {
        "base": cfg.base, "password": cfg.password + "!", "parameters": vars(cfg),
        "governor": {"username": cfg.governor, "password": gov_password + "!"},
        "admin": "ada.admin", "lead": "cyril.lead", "readers": ["reader.%02d" % i for i in range(cfg.readers)],
        "targets": targets, "teams": teams, "agent_secret": agent_secret, "gate_keys": gate_keys,
        "rounds": timings, "issues": {"open": open_issues, "all": all_issues}, "triage_decisions": triaged,
        "seconds": round(time.time() - started, 1),
    }
    with open(cfg.out, "w") as f:
        json.dump(out, f, indent=1)
    log("done in %.0fs: %d issues (%d open), written to %s" % (out["seconds"], all_issues, open_issues, cfg.out))


if __name__ == "__main__":
    main()

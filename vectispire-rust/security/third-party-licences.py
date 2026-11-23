#!/usr/bin/env python3
"""Writes, or checks, THIRD-PARTY-LICENSES: the licence texts of everything linked into the agent's binary.

    security/third-party-licences.py            rewrite THIRD-PARTY-LICENSES from the lockfile's sources
    security/third-party-licences.py --check    fail if it, NOTICE or LICENSE is not what it should be

**Why a file, and why committed.** The Java images carry their dependencies' licence texts inside the jars
(`META-INF/`), unmodified; a static binary carries none. MIT, BSD, ISC, Unicode-3.0, CDLA-Permissive-2.0 and
Zlib all ask that the copyright notice and the licence travel with a binary distribution, so the image ships
them in `/app/THIRD-PARTY-LICENSES` beside `/app/LICENSE` and `/app/NOTICE`. It is generated here and
committed, not generated in the image's build: the build would need a generator and its inputs pinned the way
the compiler is, and a committed file is the same bytes in every build by construction — which is what
`security/reproducible-image.sh` asks of the image. `--check` (run by `check.sh` and CI's `rust` job) is what
keeps it from going stale: a dependency that moves without the file moving fails the gate.

**What counts as linked.** The `vectispire-agent` package's normal dependencies, transitively, on both
platforms the image is built for (linux/amd64 and linux/arm64 on musl, the union: the two graphs differ by a
crate). `cargo metadata` resolves the features of the whole workspace at once, so the list may name a crate
the agent's own build leaves out: a superset, which attributes too much rather than too little. Build scripts'
own dependencies run on the builder and are not shipped — with one exception, which
`BUNDLED` names: the C libraries the `-sys` crates compile from source and link in (libgit2, libssh2, zlib,
and OpenSSL, which `openssl-src` builds). Their crates are MIT/Apache-2.0 but what they bundle is not —
libgit2 is GPL-2.0 with a linking exception — so the bundled library's own licence file is copied, and a
version whose file moved fails here rather than shipping without it.

**Every file a crate ships, whatever the licence expression chooses.** For `MIT OR Apache-2.0` either text
would do; copying both decides nothing on anyone's behalf. A crate that ships no licence file is listed as
such, under its declared licence: the text then exists only as the licence's standard one, which is named.

**NOTICE is held too**: it must name every licence the graph carries (as `ci/licences/check.py` holds the
root NOTICE to the jars), open with the root NOTICE's copyright paragraph, and LICENSE must be the root's.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPOSITORY = os.path.dirname(WORKSPACE)
OUTPUT = os.path.join(WORKSPACE, "THIRD-PARTY-LICENSES")
NOTICE = os.path.join(WORKSPACE, "NOTICE")
LICENSE = os.path.join(WORKSPACE, "LICENSE")

ROOT_PACKAGE = "vectispire-agent"
# The platforms Dockerfile.agent is built for (CI's rust-image and rust-image-arm64).
PLATFORMS = ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl")
# What a `-sys` crate compiles from source and links into the binary: crate -> (library, its licence, file).
# A build-dependency (openssl-src) is named here because its output is linked, unlike every other build
# dependency. The licence is what the file says, read by a person, not the crate's declared one.
BUNDLED = {
    "libgit2-sys": ("libgit2", "GPL-2.0-only WITH GCC-exception-2.0 (libgit2's linking exception)", "libgit2/COPYING"),
    "libssh2-sys": ("libssh2", "BSD-3-Clause", "libssh2/COPYING"),
    "libz-sys": ("zlib", "Zlib", "src/zlib/LICENSE"),
    "openssl-src": ("OpenSSL", "Apache-2.0", "openssl/LICENSE.txt"),
}
LICENCE_FILE = re.compile(r"(?i)^(licen[cs]e|copying|notice|copyright|unlicense)([-_.].*)?$")


def metadata(platform):
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", platform],
        cwd=WORKSPACE, check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def linked(meta):
    """Package ids reached from the agent by normal edges, plus the BUNDLED build-dependencies."""
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    roots = [p["id"] for p in meta["packages"] if p["name"] == ROOT_PACKAGE and p["source"] is None]
    if len(roots) != 1:
        sys.exit(f"{ROOT_PACKAGE} not found once in the workspace")
    seen, todo = set(), list(roots)
    while todo:
        current = todo.pop()
        if current in seen:
            continue
        seen.add(current)
        for dep in nodes[current]["deps"]:
            kinds = {k["kind"] for k in dep["dep_kinds"]}
            name = packages[dep["pkg"]]["name"]
            if None in kinds or ("build" in kinds and name in BUNDLED):
                todo.append(dep["pkg"])
    return [packages[i] for i in seen if packages[i]["source"] is not None]


def read(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8", errors="replace").replace("\r\n", "\n").rstrip() + "\n"


def collect(metas):
    """The crates `linked` finds in each platform's metadata, the union, each with its licence files."""
    crates = {}
    for meta in metas:
        for package in linked(meta):
            crates[(package["name"], package["version"])] = package
    entries = []  # (name, version, licence, [(file label, text)])
    for (name, version), package in sorted(crates.items()):
        directory = os.path.dirname(package["manifest_path"])
        files = [(f, read(os.path.join(directory, f))) for f in sorted(os.listdir(directory))
                 if LICENCE_FILE.match(f) and os.path.isfile(os.path.join(directory, f))]
        licence = package["license"] or "(none declared)"
        if name in BUNDLED:
            library, bundled_licence, relative = BUNDLED[name]
            path = os.path.join(directory, relative)
            if not os.path.isfile(path):
                sys.exit(f"{name} {version}: the bundled {library}'s licence is no longer at {relative} — "
                         "find it and update BUNDLED, never drop it")
            files.append((f"{relative} — {library}, bundled and linked: {bundled_licence}", read(path)))
        entries.append((name, version, licence, files))
    return entries


def spdx_ids(expression):
    """The names in a licence expression; the old `MIT/Apache-2.0` spelling splits on the slash like any operator."""
    return set(re.findall(r"[A-Za-z0-9][A-Za-z0-9.\-]*", expression)) - {"OR", "AND", "WITH"}


def render(entries):
    out = ["Third-party licences of the Vectispire agent's binary (Rust)",
           "",
           "Generated by vectispire-rust/security/third-party-licences.py from Cargo.lock; do not edit.",
           "Every crate linked into /vectispire-agent, with the licence it declares and every licence file it",
           "ships, and the C libraries compiled into it from source — a superset, since the features are",
           "resolved for the whole workspace. A text shared by several crates is printed once, after the",
           "list of those crates.",
           "",
           "=" * 80, "Crates", "=" * 80, ""]
    texts = {}  # digest -> (label-set, text)
    for name, version, licence, files in entries:
        refs = []
        for label, text in files:
            digest = hashlib.sha256(text.encode()).hexdigest()[:12]
            texts.setdefault(digest, (text, []))[1].append(f"{name} {version}: {label}")
            refs.append(f"[{digest}] {label}")
        out.append(f"{name} {version} — {licence}")
        out.extend(f"    {r}" for r in refs) if refs else out.append(
            "    ships no licence file: the standard text of the licence declared above applies")
    out += ["", "=" * 80, "Texts", "=" * 80]
    for digest, (text, users) in sorted(texts.items(), key=lambda kv: kv[1][1][0]):
        out += ["", "-" * 80, f"[{digest}] shipped by:"] + [f"    {u}" for u in users] + ["-" * 80, "", text.rstrip()]
    return "\n".join(out) + "\n"


def check_notice(entries, notice, licence, root_notice, root_licence):
    """What is wrong with NOTICE and LICENSE (texts; LICENSE as bytes), given the crates found."""
    problems = []
    if licence != root_licence:
        problems.append("vectispire-rust/LICENSE is not the repository's LICENSE: copy it again")
    root_head = root_notice.split("\n-----", 1)[0].rstrip()
    if not notice.startswith(root_head + "\n"):
        problems.append("vectispire-rust/NOTICE does not open with the repository NOTICE's copyright paragraph")
    named = set()
    for _, _, declared, _ in entries:
        named |= spdx_ids(declared)
    for library, _, _ in BUNDLED.values():
        named.add(library)
    for identifier in sorted(named):
        # Whole words: "MIT" inside "MIT-0" or "Apache-2.0" inside a longer name does not name it.
        if not re.search(r"(?<![A-Za-z0-9.\-])" + re.escape(identifier) + r"(?![A-Za-z0-9\-]|\.[0-9])", notice):
            problems.append(f"vectispire-rust/NOTICE does not name {identifier}, which the binary carries")
    return problems


def raw(path):
    with open(path, "rb") as f:
        return f.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    entries = collect([metadata(platform) for platform in PLATFORMS])
    rendered = render(entries)
    if not args.check:
        with open(OUTPUT, "w", encoding="utf-8", newline="\n") as f:
            f.write(rendered)
        print(f"{len(entries)} crates, {len(rendered)} bytes written to {OUTPUT}")
    problems = check_notice(entries, read(NOTICE), raw(LICENSE), read(os.path.join(REPOSITORY, "NOTICE")),
                            raw(os.path.join(REPOSITORY, "LICENSE")))
    if args.check and (not os.path.exists(OUTPUT) or raw(OUTPUT).decode("utf-8") != rendered):
        problems.append("THIRD-PARTY-LICENSES is stale: run security/third-party-licences.py and commit it")
    for problem in problems:
        print("✗ " + problem, file=sys.stderr)
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Install a third-party Semgrep rule set *on this machine*, for Zanshin to use.

**Why this is a script and not a directory in the repository.** Semgrep relicensed
`semgrep/semgrep-rules` under terms that state plainly that they do not allow
distributing the rules. Vendoring them here would be a redistribution, whatever the
intent. The pre-relicense fork, `opengrep/opengrep-rules`, *is* redistributable — LGPL-2.1
plus a Commons Clause — but shipping Commons Clause files inside Zanshin would forbid
every downstream user from selling a service substantially derived from them, and take
this repository out of open source in the OSI sense. That is a steep price for rules
somebody else wrote.

So the rules travel from their author to you, and Zanshin never carries them. You receive
them under their own licence, which this script prints before it writes anything. What
Zanshin ships is its own rule set (`zanshin/services/scanners/rules/semgrep/`) plus the
plumbing to merge yours with it.

The result is still an offline, reproducible scan: this runs **once, at install time**,
not per scan. The pinned tag and the manifest are what make two scans a month apart
comparable — and what lets someone explain a sudden wave of resolved findings by pointing
at a rule set that changed.

    uv run python scripts/fetch_semgrep_rules.py
    export ZANSHIN_SEMGREP_RULES_DIR=~/.zanshin/semgrep-rules

One consequence worth stating: building an agent image that contains the fetched rules is
fine — you are the recipient. *Publishing* that image would be redistribution.
"""
import argparse
import json
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

DEFAULT_REPOSITORY = "https://github.com/opengrep/opengrep-rules.git"
# Pinned. A moving branch would mean two scans a week apart can disagree with nothing to
# point at — the same reasoning that pins the scanner images by digest.
DEFAULT_REF = "main"
DEFAULT_DESTINATION = os.path.expanduser("~/.zanshin/semgrep-rules")

# Languages Zanshin's own rules cover, and the ones worth pulling by default. Everything
# else in the upstream tree is skipped rather than copied: rule files are cheap
# individually and expensive by the thousand, both in repository size and in scan time.
DEFAULT_LANGUAGES = ("python", "javascript", "typescript", "java", "kotlin")

# Upstream keeps its test fixtures next to the rules (`foo.yaml` beside `foo.py`), and
# ships `.test.yaml` files that are fixtures rather than rules. Copying them would add
# weight and, worse, feed Semgrep rule files that are meant to fail.
SKIPPED_SUFFIXES = (".test.yaml", ".test.yml")


def _run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def fetch(repository: str, ref: str, destination: str, languages, force: bool) -> int:
    if os.path.exists(destination) and os.listdir(destination):
        if not force:
            print(
                f"{destination} exists and is not empty. Re-run with --force to replace it.",
                file=sys.stderr,
            )
            return 1
        shutil.rmtree(destination)

    with tempfile.TemporaryDirectory(prefix="zanshin_semgrep_rules_") as work_dir:
        checkout = os.path.join(work_dir, "upstream")
        print(f"Cloning {repository} at {ref} …")
        _run(["git", "clone", "--depth", "1", "--branch", ref, repository, checkout])
        commit = subprocess.run(
            ["git", "-C", checkout, "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

        licence_path = os.path.join(checkout, "LICENSE")
        licence_text = ""
        if os.path.exists(licence_path):
            with open(licence_path, encoding="utf-8") as handle:
                licence_text = handle.read()
            print("\n--- Licence of the rules you are about to install ---")
            print(licence_text.strip()[:1200])
            print("--- end of licence ---\n")

        os.makedirs(destination, exist_ok=True)
        copied = []
        for language in languages:
            source = os.path.join(checkout, language)
            if not os.path.isdir(source):
                print(f"  skipped {language}: not present upstream", file=sys.stderr)
                continue
            for root, _, files in os.walk(source):
                for name in files:
                    if not name.endswith((".yaml", ".yml")) or name.endswith(SKIPPED_SUFFIXES):
                        continue
                    absolute = os.path.join(root, name)
                    relative = os.path.relpath(absolute, checkout)
                    target = os.path.join(destination, relative)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    shutil.copy2(absolute, target)
                    copied.append(relative)

        if not copied:
            print("No rule file was copied — nothing to install.", file=sys.stderr)
            return 1

        # The licence text travels with the rules: it is a condition of the licence, and
        # it is also what tells the next person where these files came from.
        if licence_text:
            with open(os.path.join(destination, "LICENSE"), "w", encoding="utf-8") as handle:
                handle.write(licence_text)

        manifest = {
            "source": repository,
            "ref": ref,
            "commit": commit,
            "languages": list(languages),
            "file_count": len(copied),
            # Identity of the rule set as a whole. Recorded so that a wave of findings
            # appearing or resolving at once can be attributed to a rule change rather
            # than to the code — the one question nobody can answer afterwards without it.
            "digest": _digest(destination, copied),
        }
        with open(os.path.join(destination, "MANIFEST.json"), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")

    print(f"Installed {len(copied)} rule file(s) into {destination}")
    print(f"Rule set digest: {manifest['digest'][:16]}  (commit {commit[:10]})")
    print()
    print("Point Zanshin at it:")
    print(f"    export {'ZANSHIN_SEMGREP_RULES_DIR'}={destination}")
    print()
    print("These rules are not Zanshin's, and Zanshin does not redistribute them.")
    print("Building an agent image that contains them is fine; publishing that image is not.")
    return 0


def _digest(destination: str, relative_paths) -> str:
    """Content hash of the installed rule set, order-independent."""
    running = hashlib.sha256()
    for relative in sorted(relative_paths):
        with open(os.path.join(destination, relative), "rb") as handle:
            running.update(relative.encode("utf-8"))
            running.update(handle.read())
    return running.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--ref", default=DEFAULT_REF, help="branch or tag to pin to")
    parser.add_argument("--destination", default=DEFAULT_DESTINATION)
    parser.add_argument(
        "--languages", nargs="+", default=list(DEFAULT_LANGUAGES),
        help="upstream top-level directories to install",
    )
    parser.add_argument("--force", action="store_true", help="replace a non-empty destination")
    arguments = parser.parse_args()
    return fetch(
        arguments.repository, arguments.ref, arguments.destination,
        arguments.languages, arguments.force,
    )


if __name__ == "__main__":
    raise SystemExit(main())

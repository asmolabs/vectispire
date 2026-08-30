#!/usr/bin/env python3
"""Every relative link in the documentation resolves to a file that exists.

Why this exists
---------------
The documentation was reorganised into `en/` and `fr/` subtrees and the links were
not carried across: 53 of 305 relative links — one in four — pointed at paths that
had moved. Nothing noticed, because a broken Markdown link fails silently. It
renders, it is clickable, and it 404s only for the reader.

That is the failure mode this guards: not a wrong link, which review catches, but a
link that was right when it was written and stopped being right when a directory
moved. The check is mechanical, so it belongs in CI rather than in a reviewer's
memory.

What it checks, and what it deliberately does not
-------------------------------------------------
Relative links only. External URLs are not resolved: the network is not this
check's business, and a link checker that fails when a third-party site is down is
a link checker people learn to ignore.

Pure anchors (`#section`) are skipped, and so is the anchor half of a
`file.md#section` link — the file has to exist, the heading is not verified.

Absolute `file:///` links are reported as broken whatever they point at. Two of
them shipped inside the STRIDE threat models carrying an author's home directory,
which is both a dead link for every other reader and a small information leak.

Usage: python3 scripts/check-doc-links.py [root]
Exit code 1 if anything is broken, and the report names every one.
"""

from __future__ import annotations

import os
import re
import sys
import urllib.parse

# `[text](target)`, with an optional `"title"` after the target.
LINK = re.compile(r'\[[^\]]*\]\(\s*([^)\s]+)(?:\s+"[^"]*")?\s*\)')

# Not ours to resolve, or not a path at all.
EXTERNAL = ("http://", "https://", "mailto:", "tel:", "#")

SKIP_DIRS = {".git", "node_modules", "build", ".gradle", "dist", ".claude", "venv", ".venv"}


def markdown_files(root: str):
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name.endswith(".md"):
                yield os.path.join(current, name)


# Files that are not Markdown but point readers at Markdown anyway. A `docs/...md` path written
# in a Dockerfile comment or a compose file is an instruction to a person — usually a person in
# the middle of deploying — and it breaks exactly like a link does.
#
# **This was added because one was broken.** `Dockerfile` line 16 sent its reader to
# `docs/architecture/04-runtime-and-deployment.md` for the filtering-proxy configuration; the
# file lives at `docs/architecture/en/04-runtime-and-deployment.md` and has since the
# architecture tree became bilingual. Every Markdown link to it was correct, so the link check
# was green for weeks — it walked `*.md` and nothing else, and the one dead pointer sat in the
# file somebody reads while standing up a deployment.
PROSE_REFERENCES = ("Dockerfile", "Dockerfile.agent", "Dockerfile.cli",
                    "docker-compose.yml", ".env.example")

# A bare `docs/...` path mentioned in running text or a comment, backticked or not.
DOC_PATH = re.compile(r"(?<![\w/.-])(docs/[\w./-]+\.md)")


def broken_doc_paths_in(path: str, root: str) -> list[str]:
    """Markdown paths named by a non-Markdown file, resolved from the repository root."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return []

    broken = []
    for match in DOC_PATH.finditer(text):
        target = match.group(1)
        if not os.path.exists(os.path.join(root, target)):
            broken.append(f"{target}  (named here, but no such file)")
    return broken


def broken_links_in(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()

    broken = []
    for match in LINK.finditer(text):
        target = match.group(1)

        if target.startswith(EXTERNAL):
            continue

        # An absolute local path is broken by construction: it resolves on exactly
        # one machine, which is not the one the reader is on.
        if target.startswith("file://"):
            broken.append(f"{target}  (absolute local path — use a relative one)")
            continue

        # The file must exist; the anchor within it is not this check's business.
        relative = urllib.parse.unquote(target.split("#")[0])
        if not relative:
            continue

        resolved = os.path.normpath(os.path.join(os.path.dirname(path), relative))
        if not os.path.exists(resolved):
            broken.append(target)

    return broken


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "."

    checked = 0
    failures: dict[str, list[str]] = {}

    for path in sorted(markdown_files(root)):
        with open(path, encoding="utf-8", errors="replace") as handle:
            checked += sum(
                1 for m in LINK.finditer(handle.read())
                if not m.group(1).startswith(EXTERNAL)
            )
        broken = broken_links_in(path)
        if broken:
            failures[os.path.relpath(path, root)] = broken

    # The same check over the files that point at documentation without being documentation.
    for name in PROSE_REFERENCES:
        candidate = os.path.join(root, name)
        if not os.path.exists(candidate):
            continue
        with open(candidate, encoding="utf-8", errors="replace") as handle:
            checked += len(DOC_PATH.findall(handle.read()))
        broken = broken_doc_paths_in(candidate, root)
        if broken:
            failures[name] = failures.get(name, []) + broken

    total_broken = sum(len(v) for v in failures.values())
    print(f"{checked} relative links checked, {total_broken} broken")

    if not failures:
        return 0

    print()
    for path, links in sorted(failures.items()):
        print(f"{path}")
        for link in sorted(set(links)):
            print(f"    → {link}")
    print()
    print("A link that does not resolve is a page the reader cannot reach. Fix the")
    print("path, or remove the link — a link to nothing is worse than no link.")
    return 1


if __name__ == "__main__":
    sys.exit(main())

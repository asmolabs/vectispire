#!/usr/bin/env python3
"""The database images pinned by hand agree with the ones the integration campaign runs.

Why this exists
---------------
The campaign's engines are named once, in ``Engine.java`` (``postgres:17.6-alpine``,
``mysql:9.4``), and the unit suite's fixture repeats MySQL's in ``TestDatabase.IMAGE``. Testcontainers
reads those tags. Everything else that starts one of those servers cannot: the upgrade drill's
``DB_IMAGE`` defaults (``scripts/upgrade-drill.sh``) and the MySQL job services of ``ci.yml`` and
``nightly.yml`` are pinned by patch and index digest, and Dependabot reads neither a script nor a
workflow's ``services:``. So a bump of ``Engine.java`` left them on the previous server, silently: the
context and HTTP suites, the Playwright suite and the upgrade drill would each go on reporting for a
server the campaign had stopped checking — and nothing anywhere would have said so. Their comments said
"moved by hand", which is a promise, not a check.

The rule
--------
For each pin ``<repository>:<tag>@sha256:<64 hex>``, the campaign must name the same repository, and
the pin's tag must be the campaign's tag **or extend it by dotted components**: ``mysql:9.4`` accepts
``9.4.0`` and ``9.4.12`` — Testcontainers resolves the floating minor, the pin records the patch it
resolved to — but neither ``9.40`` nor ``9.5.0``. A campaign tag with a suffix (``17.6-alpine``)
therefore has to be matched exactly. The patch itself is not compared to anything: the campaign does not
name one, and pretending it does would be a second copy of a fact nobody owns.

``TestDatabase.IMAGE`` must equal ``Engine.MYSQL`` exactly; both are Testcontainers tags.

A pin without a digest, or naming an engine the campaign does not run, fails too. A source that cannot
be read, or in which the expected pins are not found, fails: a check that passes having read nothing
is worse than no check, because it is believed. The restore drill's MySQL 8.4 comes from
``docker-compose.yml``, deliberately another line, and is not compared here.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JAVA = ROOT / "vectispire-java" / "vectispire-core" / "src"
ENGINE = JAVA / "integrationTest/java/com/asmolabs/vectispire/core/persistence/Engine.java"
TEST_DATABASE = JAVA / "test/java/com/asmolabs/vectispire/core/TestDatabase.java"
DRILL = ROOT / "scripts" / "upgrade-drill.sh"
# The workflows whose job services must carry a campaign engine; each must yield at least one, so a
# service that is renamed or moved out of reach of the pattern below fails here rather than escaping.
# Any `image:` naming either engine is read, registry prefix included: `docker.io/library/mysql:…`
# is not a repository the campaign names, so it fails rather than being skipped.
WORKFLOWS = [ROOT / ".github" / "workflows" / name for name in ("ci.yml", "nightly.yml")]

PIN = re.compile(r"^(?P<repository>[a-z0-9./-]+):(?P<tag>[A-Za-z0-9._-]+)@sha256:[0-9a-f]{64}$")


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise SystemExit(f"check-db-pins: cannot read {path.relative_to(ROOT)}: {error.strerror}. "
                         "A source that moved has to be followed here, not skipped.")


def campaign() -> dict[str, str]:
    """Repository -> Testcontainers tag, as ``Engine.java`` declares them."""
    engines = re.findall(r'^\s*([A-Z_]+)\("([a-z0-9./-]+):([A-Za-z0-9._-]+)"\)[,;]',
                         read(ENGINE), re.MULTILINE)
    if not engines:
        raise SystemExit("check-db-pins: no engine image found in Engine.java — the pattern no longer "
                         "reads it, and every comparison below would be against nothing.")
    by_repository: dict[str, str] = {}
    for constant, repository, tag in engines:
        if repository in by_repository:
            raise SystemExit(f"check-db-pins: Engine.java names {repository} twice; which one a pin "
                             "should follow is a decision this check cannot make.")
        by_repository[repository] = tag
        print(f"  Engine.{constant:<10} {repository}:{tag}")
    return by_repository


def agrees(campaign_tag: str, pinned_tag: str) -> bool:
    return pinned_tag == campaign_tag or pinned_tag.startswith(campaign_tag + ".")


def pins() -> list[tuple[str, str]]:
    """(where, image) for every hand-maintained pin of a campaign engine."""
    found: list[tuple[str, str]] = []

    drill = read(DRILL)
    defaults = re.findall(r'^\s*DB_IMAGE="\$\{DB_IMAGE:-([^}]+)\}"', drill, re.MULTILINE)
    if len(defaults) != 2:
        raise SystemExit(f"check-db-pins: expected 2 DB_IMAGE defaults in scripts/upgrade-drill.sh "
                         f"(mysql, postgresql), found {len(defaults)}.")
    found += [("scripts/upgrade-drill.sh DB_IMAGE", image) for image in defaults]


    for workflow in WORKFLOWS:
        text = read(workflow)
        name = workflow.relative_to(ROOT)
        images = [(number, match.group(1))
                  for number, line in enumerate(text.splitlines(), start=1)
                  if (match := re.match(r"^\s*image:\s*['\"]?(\S*(?:mysql|postgres)\S*?)['\"]?\s*$", line))]
        if not images:
            raise SystemExit(f"check-db-pins: no mysql/postgres service image found in {name}; the "
                             "job service moved, and this check has to follow it.")
        found += [(f"{name}:{number} services", image) for number, image in images]
    return found


def main() -> int:
    print("check-db-pins: the campaign's images")
    engines = campaign()

    failures: list[str] = []
    fixture = re.findall(r'static final String IMAGE = "([^"]+)";', read(TEST_DATABASE))
    if len(fixture) != 1:
        raise SystemExit(f"check-db-pins: expected one IMAGE constant in TestDatabase.java, "
                         f"found {len(fixture)}.")
    print(f"  TestDatabase.IMAGE {fixture[0]}")
    if fixture[0] != f"mysql:{engines.get('mysql', '<absent>')}":
        failures.append(f"TestDatabase.IMAGE is {fixture[0]} but Engine.MYSQL is "
                        f"mysql:{engines.get('mysql', '<absent>')}: the unit suite would run on a "
                        "server the campaign does not.")

    print("check-db-pins: the hand-maintained pins")
    found = pins()
    # The drill runs every engine of the campaign, so each needs its own default there: two MySQL
    # defaults would agree pin by pin and still leave PostgreSQL's upgrade unchecked.
    drilled = {image.split(":", 1)[0] for where, image in found if where.startswith("scripts/")}
    if drilled != set(engines):
        failures.append(f"scripts/upgrade-drill.sh pins {sorted(drilled)}, but Engine.java runs "
                        f"{sorted(engines)}")
    for where, image in found:
        match = PIN.match(image)
        if not match:
            failures.append(f"{where}: {image} is not <repository>:<tag>@sha256:<digest>")
            continue
        repository, tag = match.group("repository"), match.group("tag")
        expected = engines.get(repository)
        if expected is None:
            failures.append(f"{where}: {repository} is not an engine Engine.java runs")
        elif not agrees(expected, tag):
            failures.append(f"{where} pins {repository}:{tag}, but Engine.java runs "
                            f"{repository}:{expected}")
        else:
            print(f"  {where:<42} {repository}:{tag} follows {repository}:{expected}")

    if failures:
        print("\nThe database pins disagree with the integration campaign:\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print("\nMove the pin and the campaign together — the patch the campaign's tag resolves to "
              "and its index digest, from `docker buildx imagetools inspect <image:tag>`.",
              file=sys.stderr)
        return 1
    print("check-db-pins: every pin follows the campaign.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

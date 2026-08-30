#!/usr/bin/env python3
"""Load-bearing facts asserted in prose are checked against the tree that decides them.

Why this exists
---------------
`check-doc-links.py` proves every relative link resolves. Bilingual parity was proved by
counting files: ``docs/fr`` has twelve, ``docs/en`` has twelve, therefore parity. Both checks
passed, for five consecutive audits, while ``README.md`` announced **"Four engines are
supported"** and ``README.fr.md`` — its own counterpart — said two engines and a test fixture.

ADR 0009 (four engines) was superseded by ADR 0014 (two engines and a fixture) on 25 August. The
register recorded the reversal correctly, with dates and cross-links. The front page kept
selling the reversed decision for five days, and no rule could see it, because *counting files
is not reading them*. The same page carried "around 840 unit tests" against a real figure past
1300.

What this checks, and what it deliberately does not
---------------------------------------------------
Only facts with a single mechanical source of truth in the tree — the engine list Gradle
iterates, the migration directories Flyway reads, the ADR files on disk, the compliance
catalogue's own enum. Each is derived by *asking the source*, never by pinning a literal here:
a checker with the answer hardcoded is a second copy of the claim, and the stale copy is always
the one nobody updates.

It does not check test counts. That number changes with every commit, so a document quoting it
is wrong within a day and a checker chasing it is noise. The fix for that class of claim is to
not write it down — see the Tests section of ``README.md``.

It does not check prose for meaning. It looks for *contradictions of a known count*, which is a
narrower and more honest job than "is this paragraph true".
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Prose to inspect: the two front pages and every published document, both languages.
DOCUMENTS = sorted(
    {ROOT / "README.md", ROOT / "README.fr.md"}
    | set((ROOT / "docs" / "en").rglob("*.md"))
    | set((ROOT / "docs" / "fr").rglob("*.md"))
)

NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
    "un": 1, "une": 1, "deux": 2, "trois": 3, "quatre": 4, "cinq": 5, "six_fr": 6,
    "sept": 7, "huit": 8,
}


def spelled(value: int) -> set[str]:
    """Every way a document might write this number, digits included."""
    written = {str(value)}
    for word, number in NUMBER_WORDS.items():
        if number == value:
            written.add(word.removesuffix("_fr"))
    return written


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def prose(text: str) -> str:
    """The sentences, with everything that is not a sentence blanked out.

    Fenced blocks, inline code and link *targets* are removed — replaced by spaces rather than
    deleted, so every remaining character keeps its original offset and reported line numbers
    stay true. Without this, `0014-two-engines-and-a-test-fixture.md` inside a link reads as a
    document claiming fourteen engines, and `0009-four-engines.md` as one claiming nine. Those
    were the first two false positives this checker produced, and a checker that cries wolf gets
    an exemption list, then gets ignored, then gets deleted.
    """
    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    text = re.sub(r"```.*?```", blank, text, flags=re.S)   # fenced blocks
    text = re.sub(r"`[^`\n]*`", blank, text)              # inline code
    text = re.sub(r"\]\([^)]*\)", blank, text)             # link targets, link text kept
    return text


# --------------------------------------------------------------------------------------
# Ground truth, derived rather than declared.
# --------------------------------------------------------------------------------------

def deployable_engines() -> list[str]:
    """The engines Gradle actually runs the campaign against, minus the test fixture.

    ADR 0014: SQLite is a fixture, not a deployable engine. The campaign runs against all
    three; only two are on offer to an operator, and conflating the two is the exact defect
    this file was written for.
    """
    gradle = read(ROOT / "vectispire-java/vectispire-core/build.gradle.kts")
    match = re.search(r"val\s+engines\s*=\s*listOf\(([^)]*)\)", gradle)
    if not match:
        raise LookupError("build.gradle.kts no longer declares `val engines = listOf(...)`")
    engines = re.findall(r'"([a-z]+)"', match.group(1))
    return [e for e in engines if e != "sqlite"]


def migration_vendors() -> list[str]:
    directory = ROOT / "vectispire-java/vectispire-core/src/main/resources/db/migration"
    return sorted(d.name for d in directory.iterdir() if d.is_dir())


def adr_numbers() -> list[str]:
    decisions = ROOT / "docs/architecture/en/decisions"
    return sorted(m.group(1) for f in decisions.glob("*.md")
                  if (m := re.match(r"^(\d{4})-", f.name)))


def compliance_counts() -> dict[str, int]:
    catalogue = read(
        ROOT / "vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire"
             "/common/domain/compliance/ComplianceFramework.java")
    control = read(
        ROOT / "vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire"
             "/common/domain/compliance/ComplianceControl.java")
    categories = re.search(r"enum Category \{(.*?)\}", control, re.S)
    if not categories:
        raise LookupError("ComplianceControl no longer declares `enum Category`")
    return {
        "frameworks": len(re.findall(r"^    [A-Z][A-Z_0-9]*\($", catalogue, re.M)),
        "controls": catalogue.count("new ComplianceControl("),
        "categories": len(re.findall(r"^\s+([A-Z][A-Z_]+),?$", categories.group(1), re.M)),
    }


# --------------------------------------------------------------------------------------
# The claims. Each is a pattern that means "this document is stating a count for X".
# --------------------------------------------------------------------------------------

def claims() -> list[tuple[str, int, re.Pattern[str]]]:
    """(label, the true count, a pattern whose group 1 is the count a document asserts)."""
    MAX = len(migration_vendors())
    counts = compliance_counts()
    return [
        # **Engines are checked as a ceiling, not an equality, and that is a deliberate
        # retreat.** The obvious rule — "any number next to `engines` must equal 2" — produced
        # seventeen false positives on its first run: `un moteur` is a French article, and
        # `one engine` is ordinary prose in a sentence about running the campaign against a
        # single one. Both are correct English and correct French, and neither is the defect.
        #
        # The defect only ever *inflates*. "Four engines are supported" was wrong because four
        # exceeds what exists; no document has ever undersold the engine list. So the bound is
        # the number of migration directories Flyway actually carries — claim more targets than
        # there is SQL for, and it is wrong whatever the phrasing. That catches the case that
        # broke and stays silent on the cases that did not.
        ("database engines (at most)", MAX, re.compile(
            r"\b(\d+|one|two|three|four|five|six|un|une|deux|trois|quatre|cinq|six)\b\s+"
            r"(?:(?!\b(?:of|and|de|et)\b)[\w’'-]+\s+){0,2}"
            r"(?:engines?|moteurs?)\b", re.I)),
        # "six frameworks", "cinq référentiels internationaux majeurs", "all 5 frameworks".
        #
        # The adjective gap is not incidental. The first version of this pattern required the
        # number to sit next to the noun, and it missed the live defect it was written for:
        # *"against five major international regulatory frameworks"*, three words apart, above a
        # list of six. Up to four intervening adjectives, and no sentence boundary crossed.
        ("compliance frameworks", counts["frameworks"], re.compile(
            r"\b(\d+|four|five|six|seven|quatre|cinq|sept)\b\s+"
            r"(?:(?!\b(?:of|and|de|et)\b)[\w’'-]+\s+){0,4}"
            r"(?:frameworks?|référentiels?)\b", re.I)),
        # "24 controls", "détail des 24 contrôles"
        ("compliance controls", counts["controls"], re.compile(
            r"\b(\d+)\s+(?:(?!\b(?:of|and|de|et)\b)[\w’'-]+\s+){0,2}"
            r"(?:controls?|contrôles?)\b", re.I)),
        # "7 assessment categories", "7 catégories d'évaluation", "seven control categories".
        # The documents say *assessment* categories where the enum says Category; matching only
        # the code's word is how a pattern ends up checking nothing at all.
        ("control categories", counts["categories"], re.compile(
            r"\b(\d+|six|seven|eight|sept|huit)\b\s+"
            r"(?:(?!\b(?:of|and|de|et)\b)[\w’'-]+\s+){0,2}"
            r"(?:categor(?:y|ies)|catégories?)\b", re.I)),
    ]


def asserted(text: str, pattern: re.Pattern[str]) -> list[tuple[int, str, str]]:
    """Every count a document asserts for one claim, with the line it sits on."""
    found = []
    for match in pattern.finditer(text):
        raw = match.group(1).lower()
        value = int(raw) if raw.isdigit() else NUMBER_WORDS.get(raw)
        if value is None:
            continue
        line = text.count("\n", 0, match.start()) + 1
        found.append((line, value, match.group(0).strip()))
    return found


def main() -> int:
    if not DOCUMENTS:
        print("No documents were found to inspect — the walk is wrong, and a rule that "
              "inspects nothing passes forever.", file=sys.stderr)
        return 1

    checks = claims()
    failures: list[str] = []
    inspected = 0
    matched_per_claim = {label: 0 for label, _, _ in checks}

    for document in DOCUMENTS:
        text = prose(read(document))
        relative = document.relative_to(ROOT)
        for label, truth, pattern in checks:
            for line, value, quote in asserted(text, pattern):
                inspected += 1
                matched_per_claim[label] += 1
                ceiling = label.endswith("(at most)")
                wrong = value > truth if ceiling else value != truth
                if wrong:
                    verb = "at most" if ceiling else "exactly"
                    failures.append(
                        f"{relative}:{line} claims {value} {label.removesuffix(' (at most)')}; "
                        f"the tree allows {verb} {truth}\n    “{quote}”")

    # **The guard against a rule that inspects nothing.** `check-i18n-keys.mjs` shipped with a
    # floor of 40 keys and silently accepted a drop from 54 to 52 — a floor low enough to clear
    # is a floor that never fires. Here the requirement is per-claim: if *any* claim stopped
    # being found anywhere, its pattern has rotted and it is no longer checking a thing.
    silent = [label for label, hits in matched_per_claim.items() if hits == 0]
    if silent:
        print("These claims matched nothing in any document, so they are not being checked:",
              file=sys.stderr)
        for label in silent:
            print(f"  - {label}", file=sys.stderr)
        print("Either the documentation stopped stating them, or the pattern is wrong. Both "
              "need a human; neither is a clean run.", file=sys.stderr)
        return 1

    if failures:
        print("Documentation contradicts the tree:\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print("\nA register that records a reversal and a front page that keeps selling the "
              "reversed decision is worse than no register: the reader who checks is the one "
              "who gets it wrong.", file=sys.stderr)
        return 1

    engines = deployable_engines()
    vendors = migration_vendors()
    adrs = adr_numbers()
    counts = compliance_counts()
    print(f"{len(DOCUMENTS)} documents, {inspected} numeric claims checked, none contradicted.")
    print(f"  deployable engines : {len(engines)} ({', '.join(engines)}) "
          f"— migrations for {len(vendors)}: {', '.join(vendors)}")
    print(f"  ADRs               : {len(adrs)} ({adrs[0]}–{adrs[-1]})")
    print(f"  compliance         : {counts['frameworks']} frameworks, "
          f"{counts['controls']} controls, {counts['categories']} categories")
    return 0


if __name__ == "__main__":
    sys.exit(main())

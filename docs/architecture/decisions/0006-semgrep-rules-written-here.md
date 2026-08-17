# 0006 — The Semgrep rules are written here, not redistributed

**Date:** 2026-08-07 · **Status:** accepted

## Context

The plan was to vendor an upstream rule set into the repository, the way the analyzer
images are: the scan stays offline, and it is reproducible.

That plan ran into a licensing constraint discovered along the way.

- **`semgrep/semgrep-rules`** was relicensed under terms that **explicitly forbid
  distributing the rules**. Vendoring is therefore impossible.
- **`opengrep/opengrep-rules`**, the fork taken before that change, remains
  redistributable — but under LGPL-2.1 **plus a Commons Clause**. That clause would take
  Zanshin out of open source in the OSI sense and would bind everyone who takes it up.

## Decision

Three sources, in this order.

**Zanshin's own rules**, written here, with no third-party license: about forty, Python /
JS-TS / Java, security and quality. Few in number and high in signal.

**A directory supplied by the operator** (`ZANSHIN_SEMGREP_RULES_DIR`), merged with the
previous one. That is where the rules they choose land.

**A fetch script** (`scripts/fetch_semgrep_rules.py`) that pulls `opengrep-rules` at a
pinned tag, installs it into that directory, prints the license and writes a manifest.
**Once, at install time, not on every scan**: the scan stays offline and reproducible, and
the operator receives the rules from their author without Zanshin redistributing them.

## What was rejected

**Accepting the Commons Clause** to get a large rule set for free. It is a bad price:
Zanshin would stop being free in the OSI sense, and the restriction would bind whoever
takes it up — for rules written by somebody else.

**Downloading the rules on every scan** from the `semgrep.dev` registry. The registry also
serves proprietary rules, its terms restrict bulk downloading, and above all a scan would
stop being reproducible and offline — which is this tool's main property.

## Consequences

**Updating the rules is a deployment, not a button.** An accepted consequence of the
offline choice, to be written plainly in the Settings screen.

**Building an agent image containing the fetched rules is a clean use; publishing that
image would be redistribution.** To be said in the documentation, because nobody will guess
it.

**A rule set that contains no quality rules would resolve every quality finding** — both
types enter the scanned-types list together. Likewise, recategorizing a rule upstream
destroys the issue's history, since the type enters the fingerprint. There is no clean
counter-measure; hence the recorded manifest, so that a mass movement has at least an
explanation.

**`--no-rewrite-rule-ids` is indispensable.** With a `--config` pointing at a directory,
Semgrep prefixes every `check_id` with the rule's relative path: reorganizing `rules/`
would therefore rename every identifier, which **would resolve every SAST finding and
recreate them as new, triage lost**.

**The rules are copied into the scan's workspace.** Counter-intuitive but mandatory: volume
paths are resolved by the Docker *daemon*, not by the Zanshin process, so a directory
living inside Zanshin's image is invisible to the sibling Semgrep container.

---

> **Note added 2026-08-17, outside the decision text.** An earlier note here claimed the
> first two sources still worked. That was wrong, and the audit that followed found all
> three broken by the port:
>
> - **Zanshin's own rules**: one rule, not "about forty, Python / JS-TS / Java".
> - **`ZANSHIN_SEMGREP_RULES_DIR`**: documented in the README and in the settings table,
>   and read nowhere in the code. Implemented on 2026-08-17 in
>   `scanning/bundled-rules.ts`, with a directory that cannot be read now failing SAST
>   rather than letting the scan run with the bundled rules alone.
> - **The fetch script**: not ported. The manual procedure is in the README; a wrapper
>   around a pinned download did not earn a second tool to maintain.
>
> The decision itself is untouched: its licensing and offline-reproducibility argument is
> as sound as the day it was written. What was missing was the code, which is why this is
> a note and not a superseding page.

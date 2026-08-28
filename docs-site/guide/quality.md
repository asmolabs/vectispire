# Code quality

Semgrep produces two kinds of finding, and Vectispire keeps them apart on purpose.

**Security findings** are gated like any vulnerability: they count towards a policy and
they can fail a build.

**Quality findings** are visible in the backlog and **can never fail a CI gate**. Not by
configuration — by construction.

The reason is worth stating. A gate that can fail on style is a gate that teams learn to
bypass, and once bypassing is routine the security half stops working too. The quality
backlog is there to be read and worked through, not to block a release.

## The Quality section

Ranked three ways, because the useful question differs by who is asking:

- **By rule** — which rule fires most across the estate. This is the one that finds a
  systemic problem worth a codemod rather than a hundred individual fixes.
- **By file** — the files that concentrate the debt.
- **By repository** — where to send the effort.

## Enabling it

Semgrep is **off by default** and analyses source code directly — a concatenated SQL query,
a command handed to a shell, an unverified TLS certificate. No other scanner here sees any
of that. It runs with the network disabled like every other scanner.

**Vectispire bundles a single rule.** That is a licensing constraint rather than an
oversight: the public rule sets are not redistributable. Real coverage comes from a rule
set you install yourself.

[Installing a Semgrep rule set →](../administration/rule-sets.md)

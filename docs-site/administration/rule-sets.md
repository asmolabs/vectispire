# Semgrep rule sets

Semgrep reads the source code itself — a concatenated SQL query, a command handed to a
shell, an unverified TLS certificate. No other scanner here sees any of that.

It is **off by default**, and it runs with the network disabled like every other scanner.

## Why you have to install rules yourself

**Vectispire bundles a single rule.**

That is a licensing constraint, not an oversight: the public Semgrep rule sets are not
redistributable. Shipping them would put a redistribution problem into every deployment of
this product.

So real coverage comes from a rule set you install. Enabling Semgrep without one gets you
one rule's worth of findings and a false sense of coverage — which is worse than leaving it
off.

## Installing one

Obtain a rule set under a license that permits your use, and register it on **Rule sets**.
Semgrep's own registry, your organisation's internal rules, or a vendor's — the constraint
is on Vectispire redistributing them, not on you running them.

## Security and quality

Semgrep findings arrive in two kinds:

- **security** — gated like any vulnerability;
- **quality** — visible in the backlog, and they **can never fail a CI gate**.

That boundary is structural rather than configurable. See
[Code quality](../guide/quality.md).

## Rolling it out

Expect a large first result on an existing codebase. Enable it on one repository, work
through what it says, tune the rule set, and only then widen — turning it on estate-wide in
one go produces a backlog nobody triages and a feature everybody ignores.

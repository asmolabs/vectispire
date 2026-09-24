---
name: security-audit
description: Runs a security review of Vectispire in four parallel read-only areas (authentication, authorization, injection/SSRF, crypto/secrets/browser/deployment) with the security-reviewer agent, verifies the most serious findings in the code, and returns one deduplicated report ranked by severity. Use when asked for a security analysis, a security audit, or a review of a security-sensitive change.
---

# Security review

## 1. Scope

- **Whole application** (default): the four areas below.
- **A change**: pass the diff range (`git diff <base>..HEAD`) to each reviewer and ask them to review
  the change *and* what it touches, not the whole codebase.

## 2. Fan out — four `security-reviewer` agents, in parallel, in the background

One per area, each told to read `AGENTS.md` first, verify before reporting, and use the report format
of the agent definition:

1. **Authentication** — login, sessions, MFA and its limits, lockout and throttles (what they are
   keyed on), API keys, agent keys, SCIM token, SSO/OIDC linking, timing, bootstrap and example
   credentials.
2. **Authorization** — every route that takes an id or aggregates data: visibility applied in the
   query, 404 not 403; role checks against `Role` flags, not markers alone; who may grant which
   role; four-eyes; anonymous routes; mass assignment.
3. **Injection and SSRF** — outbound destinations a non-administrator can set (Docker proxy and
   database reachable?), argument and path injection, repository content parsed in the JVM (symlinks,
   size, regex), XML/YAML/JSON parsing, SQL, CSV/PDF/notification output, container hardening.
4. **Crypto, secrets, browser, deployment** — encryption at rest and what happens when the key is
   lost, signing keys (persistence, public half matching), verification routes, DSSE, webhook HMAC,
   audit chain, randomness, XSS sinks and token storage, headers, Dockerfiles, compose topology,
   workflow permissions.

Continue other work while they run; do not predict their results.

## 3. Verify

When all four have reported, **confirm the critical and high findings yourself** in the code — open
the file at the cited line, follow the guard — and mark each one ✔ verified or ✘ not reproduced.
Findings reported independently by two areas are strong signals; say so.

## 4. Report

One report, deduplicated across areas, ranked **critical/high → medium → low**, each with the file,
the scenario in one or two sentences and the fix; then what the areas found sound; then a proposed
order of correction (group findings that share a cause — e.g. the role model — into one change).

**The repository is public.** Do not commit the report or write it under `docs/` before the fixes
land. Keep it in the conversation, or offer a private page.

## 5. Fixing

Fix in the proposed order, one commit per cause, each with tests that fail without the fix
(mutation-checked), then run the `quality-gate` skill before pushing.

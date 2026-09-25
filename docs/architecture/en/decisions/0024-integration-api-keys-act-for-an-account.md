# 0024 — An integration API key acts for one account, on the routes that accept it

**Date:** 2026-09-25 · **Status:** accepted · **Decider:** Laurent Boucher

## Context

The API keys screen issued keys with `read`, `scan` and `export` scopes, and none of them
authenticated anywhere: the bearer filter accepted only an agent's own key. The OpenAPI document
advertised an `X-API-Key` scheme, and the CI gate documentation told people to use an API key, while
the gate script sent a user session. Tools that must call Vectispire without a person at a browser —
a CI pipeline, SonarQube, a reporting script — had no credential meant for them.

A second fact shaped the decision: `@RequiresAccount` checks only that the caller is authenticated,
and an agent key is authenticated. Nothing confined a non-session credential to the routes meant for
it; an agent key reaching an account route saw an empty visibility, which is a consequence rather
than a rule.

## Decision

- **An integration key acts for the account that issued it.** It carries that account's role and
  visibility, narrowed further by the key's optional target restriction — the restriction is
  enforced again. A key whose account is deactivated or deleted stops working.
- **A non-session credential reaches only the routes that declare it.** A route accepts an
  integration key by carrying `@AcceptsApiKey(scope)`; a key without that scope, or on a route without
  the marker, is refused (403 — the route exists for its owner, and saying so reveals no target).
  Agent keys are confined the same way to the routes marked `@RequiresAgentKey`. The role markers
  still apply on top, so a key never exceeds its account.
- **Scopes are route families:** `read` (issues, scans, SBOMs, compliance, gate verdicts), `scan`
  (trigger a scan, evaluate the gate), `export` (VEX, CSAF, SARIF, CycloneDX, reports). Nothing
  administrative accepts a key. The `agent` scope is not issued from this screen: an agent's key is
  created with the agent.
- The key is presented as `Authorization: Bearer <key>` or `X-API-Key: <key>`. It is stored hashed,
  looked up by its prefix, expires when set to, is revoked by deleting it, is rate-limited per key,
  and every write it performs is audited in its account's name with the key named beside it.

## Consequences

- One migration: `t_api_key.owner_user_id`. Keys issued before it have no owner and authenticate
  nowhere, as before; they are listed as such and should be reissued.
- The confinement also closes the agent-key hole above.
- A key is as powerful as its account within its scopes: issue integration keys from an account
  whose role and visibility fit the integration, or restrict the key to its targets.

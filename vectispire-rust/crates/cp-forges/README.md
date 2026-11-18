# vectispire-cp-forges

Forges (decision 0037) — Java's `core.forges`: read-only connections to GitHub and GitLab, the discoveries of their
repositories, the selection and the import of them as ordinary targets, and the change-review readings the checklists
judge. Wave 2 of the port; the fourteen routes of `/api/v1/forge-connections` and the maintenance slots
`FORGE_TOKEN_WATCH` and `CHANGE_REVIEWS`.

| | |
|---|---|
| `connections.rs` | `ForgeConnectionService`: the token probed through the outbound door before anything is kept, sealed with its row as context, never answered; the two signalled refusals; the census line |
| `discoveries.rs` | `ForgeDiscoveryService`: one run per connection at a time, queued and polled; the snapshot per run |
| `imports.rs` | the selection (filters, operations), the preview and the import — up to 1,000 targets in one transaction through `cp-targets`' own gestures (`ImportBatch`), the provenance link in that transaction |
| `reviews.rs`, `change_reviews.rs` | the hourly reading of how changes reach a branch, and the checklists' `ReviewEvidence` port over what was read |
| `token_watch.rs` | the tokens' expiries announced once per change (`TokenAlert`, in `vectispire-domain`) |
| `purge.rs` | a deleted target's link and readings, in the deleting transaction |
| `internal/` | targets and trust, the probes, the listers, the discovery's queue, execution and worker, the import planner, the review readers |
| `persistence/` | the five tables as SeaORM entities (`t_forge_connection`, `t_forge_discovery`, `t_forge_repository`, `t_forge_import_link`, `t_forge_review_reading`), held to the schema by the parity suite; no `.sqlx/` cache, every statement a builder's |

**Every request to a forge goes through `cp-outbound`**: `OutboundJson.answer` for a probe, `OutboundPager` for a
listing or a reading — the guard, the pinned address, the pinned CA, no redirect, the next page on the same origin and
under the API's root only.

**Known differences from Java, on purpose:**

- An import's first scans are queued **after** the import's transaction commits: the scans' owner writes in a
  transaction of its own, which would wait on the batch's uncommitted rows. Java's `TargetScans` joined the import's
  transaction. A scan that cannot be queued after a committed import is logged and the target left to its schedule.
- A probe refused for a certificate no anchor vouches for quotes rustls' words, not the JDK's PKIX sentence (the one
  recording that compares it is in `golden/deferred/_recording.txt`).
- `TokenAlert`'s listener is `notifications`', not ported yet: `AuditedAlerts` writes the alert's audit entry (and
  through the log the SIEM event) and no channel message, until that module replaces it.
- A GitHub token expiry stated with a region's zone name (`Europe/Paris`) reads as not reported: the domain crate
  carries no zone rules; GitHub writes `UTC`.

**The replay's stub forge.** The forge route tests start `ForgeStub.fixture()`, whose CA key is a fixed scalar, and the
recorder keeps every answer the stub gave (`outbound` in the manifest). The golden replay stands up a TLS stub per
origin under that CA and answers the requests made during each recorded request with Java's stub's answers; what the
tests drove themselves (a discovery's drain, a reading's turn) is the next request's seed.

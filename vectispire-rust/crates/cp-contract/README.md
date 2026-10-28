# vectispire-cp-contract — the control plane's contract, kept identical

Task 0.4 of the Rust port of the control plane (plan §3.4, §4.3, §7: `docs/analysis/en/2026-10-16_rust_control_plane_port_plan.en.md` on branch `docs/rust-control-plane-plan`, not on this branch yet).

The Angular client is generated from `openapi.json`, the agents call eight of its routes and customers'
pipelines call the CLI and the gate against it. **The document is what the port must not change**, so the
port is held to it by this crate — and the crate is held to the document by copies it cannot edit its way out
of.

## What it checks

| Check | Against | Fails when |
|---|---|---|
| `check_routes` | the routes the router **declares** (`RouteDecl`: method, path, operation id, query and header parameters, security) | a documented route is not served, a served route is not documented, a method, parameter, `required` flag, operation id or security scheme differs |
| `probe` | the router **itself**: each documented request is sent to it (no credential, parameters filled with `1`) | a route was declared and not registered, or registered under another method (`405`) |
| `Schemas` | the document's JSON Schema (2020-12) | a handler type serialized (`assert_serializes_as`), a replayed answer or a recorded one does not satisfy the schema of its operation, status and media type |
| `replay` | recorded Java traffic | a status, header, body (key order, number text), or the rows a request touched differ — each reported by JSON Pointer |
| `check_published` | `reference/published-operation-ids.txt` | a published operation id is renamed, removed, or registered under another id; two operations share an id |

**Why the router declares its routes.** An axum `Router` cannot list the routes it holds. The control
plane's route builder (task 0.3) records each route as it registers it; `RecordingRouter` is the same idea
for a test. A declaration could lie, so `probe` is the other half: it asks the router. Two limits, both
tested: the probe cannot see a literal route shadowed by a parameter route (`/things/export` is answered by
`/things/{id}`) — the declaration table sees it; and it runs the handlers, so it is pointed at a router built
with test doubles and without an authentication layer.

## The things that are copies on purpose

- `reference/openapi.json` — the document the Java control plane serves, **as of the 0.11.1 line**
  (`b8bd7e8d0`), the line the port targets. Embedded, so no check can be pointed at another file.
- `reference/published-operation-ids.txt` — the Java side's list, which moves by hand.
- `reference/not-yet-ported.txt` and `.ceiling` — every route not ported yet: **311 today, and the list only
  shrinks**. A route that is now served must be deleted from it, a route the document does not list cannot be
  added, a list above its ceiling fails, and so does one *below* it — the ceiling is lowered in the commit that
  ports the route, so that nobody spends the slack on a route they have not ported.

`reference/refresh.sh <commit>` moves the first two, by hand, in a commit that says why; then
`cargo run -p vectispire-cp-contract -- allowlist-write` regenerates the allowlist for a router that serves
nothing. It is never run to make a check pass.

## The recorder's goldens (`recorded`, task 2.11)

The Java suite's traffic as `TrafficRecorder` writes it (`vectispire-java/…/core/golden/README.md`): a manifest, one
file per request with its `seed`, `response` and `effect`, identities as ranks (`«t_repository#1»`), credentials and
clock values as placeholders. **Generated, not committed**; `scripts/replay-goldens.sh <dir>` records the suite at the
commit (or takes a recording already there) and runs, in order, `cp-contract replay-plan` (every recording of a route
not served, or outside the contract, covered by `golden/deferred.txt`) and each served module's `golden` test on MySQL
9.4 and PostgreSQL 17. That test is `#[ignore]`d by a plain `cargo test`, which reports it as ignored.

How a test is replayed (`recorded::replay`):

1. The tables are emptied and the baseline's (the audit chain's head) put back as the migrations wrote them, then
   checked against the manifest's `baseline`. Each identity counter is placed in the table's range from the
   manifest's `idBases`, as the recorder places them; a test's ranks count from the counter it starts at.
2. File by file: the `seed` is written (one transaction, foreign keys unchecked, PostgreSQL's sequences moved past
   the ids written). A request to a route the router serves is sent to a router built for this test, the tables
   read before and after, and the answer and the rows changed held to the recording. A request to a route not served
   is **played in Java's place**: its recorded `effect` is written as a seed, so the requests after it start from
   Java's state.
3. A value the replay cannot choose (a `«sealed»` credential, a blob, a PEM block, a `#prior` id, a binary or
   `https` request, a `concurrent` record, an `async` half that is not one of a clean pair) stops the test there: every recording after it is reported
   unreplayable with the reason, never compared against a state that is not Java's.

**The comparison is template matching, not normalisation** (`recorded::placeholders`). Every literal must be in the
Rust answer as written. A placeholder covers a value only of the shape the recorder's rule replaces, and:

| Placeholder | Holds the Rust value to |
|---|---|
| `«t_x#N»` | exactly `start + N - 1` — computed, not bound; as a JSON number or a string (the recorder wrote both alike; the type is the schema's or the column's to hold) |
| `«uuid:N»`, `«sha256:N»`, `«n:N»`, `«port:N»`, `«pem:…:N»`, `«secret:N»` | one value per ordinal in the test, and never another ordinal's value |
| `«sha256(secret:N)»`, `«secret:N:prefix»` | the secret's SHA-256 hex, its first twelve characters (checked when the secret is known, however late) |
| `«password-hash(…)»` | a hash that verifies against the fixture's passphrase or secret `N` (cp-access's own `phc::verify`); `(?)` one that does not hold the fixture |
| `«date»`, `«datetime»`, `«instant»`, `«http-date»`, `«stamp»` | that format, in the recorder's window (three years back, eleven ahead) |
| `«sealed»`, `«one-time-code»`, `«window»`, `«clock-step»` | the shape only — what the recorder threw away |

Objects are compared as unordered maps (README § Bodies); arrays in order; an answer's numbers as written, a row's by
value. Headers: every recorded one, with its value, and none besides but the transport's (`content-length`, `date`,
`transfer-encoding`, `connection`, `keep-alive`). Rows: every table, a table keyed by its identity in id order, any
other matched row for row as a set; a column change that renders alike under the recorder's rules that number nothing
(`dropUnchangedUpdates`) is not a change. The replayed answer is checked against `openapi.json`, and a violation
Java's recorded answer has too is the document's, not reported.

**Credentials are minted with `cp-access`'s code** (`Minting`, implemented by the caller since this crate uses no
module): session tokens and their hashes, API keys (when the test ever shows the key's prefix), Argon2id hashes of the
fixture or a minted secret. Nothing is hard-coded. Three choices of the replay's own, each a reason a difference could be
missed, so they are narrow:

- **a clock value seeded** is the wall clock, a microsecond after the previous one; a column named for an expiry
  (`expire`, `until`) a day ahead, since a session seeded as expiring now refuses its own request;
- **a bearer the recording never tied to its session**: the recorder collects a file's credentials before rendering
  that file, not the earlier files, so a session seeded in file 3 and presented in file 5 shows as a bare
  `«sha256:K»` in `t_session.token_hash`. Its token is minted when seeded and handed to the first unbound
  `«secret:N»` an `Authorization` header presents. A wrong pick is a refusal or another account's answer — a
  difference, never a green;
- **a rate window seeded** (`«window»` in `t_rate_window.window_key`, a webhook's hit played in Java's place) is the
  epoch's, `0`: a window long over, so a served route counting the same subject starts its own and its count differs
  from Java's rather than agreeing by luck. A request naming a window is still not replayable.

## The golden file (the first fixtures' format)

One JSON file per recorded request, written by the traffic recorder on the Java side (task 0.5). **Where the
recorder's README says otherwise, it wins and `Golden::from_json` is adapted** — the format is read in that one
function.

```json
{
  "name": "checklistContacts/an-auditor-sees-not-reminded",
  "request":  { "method": "GET", "path": "/api/v1/projects/7/checklists/contacts",
                "query": { "a": "1" }, "headers": { "Authorization": "Bearer <session>" } },
  "response": { "status": 200, "headers": { "content-type": "application/json" },
                "body": { "any": "json" }, "keyOrder": true },
  "db": { "before": { "t_user": [ { "id": 1 } ] }, "after": { "t_user": [ { "id": 1 } ] } }
}
```

`body` is a JSON value (read with its key order and number text kept) or `"bodyText"` for anything else;
`query` is an object or a `a=1&b=2` string. `normalisation.json` beside the goldens lists what the recorder
replaced (`stringPatterns`, `keyPlaceholders`, `volatileHeaders`); the standard rules — timestamps, UUIDs,
`zsk_…` keys, the headers a server sets per answer — always apply, and applying a rule twice changes nothing.

A server to replay against implements `Server` (`prepare`, `send`, `db_effects`): `AxumServer` runs a router in
process, `HttpServer` reaches one over HTTP, and a seeding and a dumping hook put the rows in and read them
back. A server that cannot dump rows is *counted* (`rows_not_compared`), and fails the replay when it was told
to require them.

## Known limits, said once

- **A nullable enum that does not list `null` rejects `null`.** On the 0.11.1 line `type: ["string","null"]`
  with an `enum` lacking `null` makes the Java application's own `"warning": null` violate its document (the
  0.12 contract adds `null` to those enums). `Schemas::admitting_null_in_nullable_enums(true)` reads them as
  admitting it, for a replay of Java traffic; a test pins the defect with the leniency off.
- **A recorded answer with placeholders cannot satisfy its schema** (`"<id>"` is not an integer), so the
  *replayed* answer is checked as the server sent it, and the recorded one only when `check_recorded` is set.
- A lone UTF-16 surrogate in a JSON string is read as U+FFFD (a Rust `String` cannot hold it); no response of
  the control plane produces one.
- axum is allowed here by `deny.toml`'s `wrappers` entry, and only here and in the control plane's own crates;
  the agent's graph is checked independently by `crates/agent/tests/isolation.rs`.

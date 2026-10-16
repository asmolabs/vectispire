# Golden traffic: the format

The Java HTTP suites are the oracle the Rust control plane is checked against (port plan §4.3, task
0.5). `TrafficRecorder` writes every request those suites perform through `MockMvc`, with its response
and the rows it touched, to one JSON file per request. The Rust replay runner (task 0.4,
`golden::replay(dir)`) seeds the same rows, sends the same requests over real HTTP and compares. This
file is the format the two sides agree on. When it and `TrafficRecorder`/`Placeholders`/`RowSnapshots`
disagree, the code is right and this file has a bug.

## Recording

```bash
cd vectispire-java
./gradlew :vectispire-core:test -Pvectispire.golden.dir=/abs/path/goldens          # the whole suite
./gradlew :vectispire-core:test --tests '*AuthRoutesTest' -Pvectispire.golden.dir=…  # one class
```

**Off unless the property is given.** Unset, `TrafficRecorder.wire` returns the builder it was given
and the extension returns at its first line, so the build that runs on every push runs exactly the
suite it ran before the recorder existed. The Gradle property becomes the system property
`vectispire.golden.dir` and the directory becomes an output of the `test` task, so a recording is never
answered by an up-to-date check. The recorder empties a directory that holds a `manifest.json` from a
previous recording and refuses any other non-empty one.

Recording costs time: two reads of every table per request on a connection of the recorder's own, and
a reset of the tables' identity counters before each test.

## Layout

```
<dir>/manifest.json
<dir>/<class>/<test>--<NNN>-<METHOD>-<path slug>.json
```

- `<class>` is the test class's binary name without `com.asmolabs.vectispire.core.`, `$` written `.`:
  `api.AuthRoutesTest`, `api.ChecklistContactsRoutesTest.Linking` for a `@Nested` class.
- `<test>` is the method name, `#<n>` added for an invocation of a parameterised or repeated test.
- `<NNN>` is the request's rank in the test, from 001, in the order MockMvc performed them. Requests in
  `@BeforeEach` methods count as the test's.
- The slug is the request path with everything outside `[A-Za-z0-9._-]` written `_`, cut at 80
  characters: a reading aid. The rank, not the slug, orders the files.

Names depend only on the tree: two recordings of the same commit have the same files.

## The manifest

```json
{
  "format": 1,
  "idStride": 1000000,
  "idBases": { "t_repository": 3709000000, "t_user": 4579000000, … },
  "totals": { "classes": …, "tests": …, "requests": … },
  "classes": [
    { "class": "api.AuthRoutesTest", "directory": "api.AuthRoutesTest",
      "tests": [
        { "name": "loginReturnsTheContract", "outcome": "passed",
          "baseline": { "t_audit_chain_head": [ { "id": 1 } ] },
          "files": [ "loginReturnsTheContract--001-POST-api_v1_auth_login.json" ],
          "notes": [ … ] } ] } ],
  "recorderFailures": [ … ]
}
```

- Classes and tests are in name order, never in the order they ran. Nothing in the manifest changes
  between two recordings of the same tree.
- `outcome` is `passed`, `failed` or `aborted`. **A failed test's goldens are not an oracle**: replay
  only `passed`.
- `baseline` is every table that holds rows once the harness has emptied the rest, before the test
  seeds anything. In practice that is the audit chain's head (V66), which the migration seeds. The
  replay starts each test from this state.
- `notes` lists what the recorder could not do for this test, such as a table whose identity counter
  it could not reset or a request it could not record. `recorderFailures` gathers the same across the run.
- `idBases` gives each table's identity base (see *Identities*).

## One request

```json
{
  "format": 1,
  "test": { "class": "api.AuthRoutesTest", "method": "loginReturnsTheContract", "invocation": "2" },
  "sequence": 1,
  "async": "started" | "dispatch",
  "concurrent": true,
  "request":  { … },
  "seed":     { <table>: <changes> },
  "response": { … },
  "effect":   { <table>: <changes> }
}
```

`invocation`, `async` and `concurrent` appear only when they apply.

### `request`

| field | |
|---|---|
| `method` | the HTTP method |
| `path` | the request URI, without the query |
| `query` | the raw query string the test wrote in the URL, when it wrote one |
| `params` | every request parameter, `name → [values]`, in the order set. It includes the query's. A parameter that is in `params` but not in `query` was set with `.param(…)`. Send it in the query string, or as a form body when the request's content type is `application/x-www-form-urlencoded` |
| `headers` | `"Name: value"` strings, in the order set, one per value. `Content-Length` is left out because the client computes it |
| `cookies` | `[name, value]` pairs |
| `remoteAddr` | only when not `127.0.0.1`. The test set the peer address; replay it through a trusted proxy's `X-Forwarded-For`, or skip the request if the runner cannot |
| `scheme` | only when not `http` |
| `body` | see *Bodies* |

### `response`

| field | |
|---|---|
| `status` | the status code |
| `errorMessage` | the reason given to `sendError`. MockMvc keeps it, and a real container drops it on the way to the error page, so **do not compare it**. It is there to explain an empty body |
| `forwardedUrl`, `redirectedUrl` | MockMvc's record of a forward or a redirect |
| `headers` | `"Name: value"` strings, in the order the server set them |
| `body` | see *Bodies* |
| `thrown` | instead of all of the above: the exception class that escaped the filter chain. MockMvc passed it to the test, and a container would have answered 500 |

### Bodies

```json
{ "contentType": "application/json", "json": <document> }
{ "contentType": "text/csv", "text": "…" }
{ "contentType": "application/pdf", "length": 1234, "sha256": "…" }          // a response
{ "contentType": "application/octet-stream", "length": 9, "sha256": "…", "base64": "…" }  // a request
```

- **JSON**, which is anything whose content type contains `json`, or that has no content type and
  starts with `{` or `[`, is parsed. Numbers are kept as written: a float is read as a decimal, and
  trailing zeros are kept.
  - A **response's** fields are in the order the server wrote them. The replay should compare objects
    as unordered maps, because Java serialises some maps built with `Map.of` in an order the JVM draws
    at start-up. The order is still recorded.
  - A **request's** fields are sorted by name, for the same reason: the test wrote them from a `Map.of`
    as often as not. A request body is shown as `json` only when the compact serialisation of what was
    parsed gave back its exact bytes. Send `json` bodies compact (no whitespace), in the sorted order.
    Anything else is shown as `text` and sent byte for byte. A signed webhook's signature covers bytes.
- **Text** covers `text/*`, `xml`, `yaml`, `csv`, form bodies and `javascript`, as long as the bytes
  decode in the declared charset (UTF-8 by default).
- **Anything else** is binary: its length and SHA-256, plus the bytes in base64 for a request, because
  the replay has to send them. A PDF or an xlsx is compared by phase 5's own means, not by its digest.
  The digest pins only bytes the server produces identically on every run.

### `seed` and `effect`: the rows

The recorder reads **every table** except `flyway_schema_history`:

- before the request, which gives `seed`: what changed since the previous request, or since the
  baseline for the first one. These are the rows the test wrote itself through repositories, or the
  writes that landed after the previous request returned (an async completion).
- after it, which gives `effect`: what the request changed.

```json
"t_session": {
  "inserted": [ { <column>: <value>, … } ],
  "updated":  [ { "key": { "id": 4579000001 }, "changed": { "last_used_at": { "from": null, "to": "«datetime»" } } } ],
  "deleted":  [ { <column>: <value>, … } ]
}
```

- Tables are in name order. Columns are in their declared order and lower case. A table, or a kind
  of change, with nothing in it is omitted.
- Rows of a table whose key is its identity column are in id order, which is creation order. Rows keyed by anything else (a random UUID, a hash) are sorted by their content with
  every random part masked (`Placeholders.mask`). Sorted by the raw key, two such rows swapped places
  between runs.
- A table without a primary key uses the whole row as its key. A repeated row is ranked.
- An update whose changes are all equal once normalised (a timestamp moving from one instant to the
  next) is **dropped**. Whether it happens at all depends on how long the previous request took.
- Values are JSON scalars. A `datetime` column is ISO-8601 without a zone before normalisation. A blob
  is written `«bytes:<length>:<first 16 hex of its SHA-256>»`.
- A table holding more than 5,000 rows before or after the request is shown as
  `{ "overCeiling": true }` and nothing else. It is read with a limit and no order, so the rows past
  the ceiling are whichever the engine returned first. In the HTTP suite only `t_epss_score` reaches
  it, in `EpssSyncRoutesTest`.
- **Concurrent requests**: when a test overlaps requests on several threads, the recorder cannot tell
  which rows each one touched. Those records carry `"concurrent": true` and no `seed` or `effect`.
  Their ranks follow the order they started, which the threads decide, so they are **not
  deterministic**. The next request alone starts from the tables as they stand.

### Async requests

A long-polled route (the agent's `jobs`) shows as two records. The first is `"async": "started"`: its
`effect` is whatever the handler wrote before it suspended, and its response is usually empty. The
second is `"async": "dispatch"`, with the same request and the final response. Over real HTTP they are
one exchange. The replay merges them: the request from the first, the response from the second, and
the union of the two effects.

## Identities

Once per database, the recorder sets each table's identity counter to a base of its own:
`(100 + CRC32(table name) mod 900) × 1 000 000`, probed upward on a collision, with tables taken in
name order. That gives nine digits and a million ids per table, and no two tables share a range. A
new table moves only the tables it collides with. `manifest.json` lists the bases. After that the
counters only grow, as they do in production.

A golden writes an id as **its table's rank in the test**: `«t_repository#1»` is the first
repository the test created, whatever number the server gave it. This applies to a JSON integer, and
to a nine-digit run with no letter or digit beside it in a string (a path, a description). The range
says which table the number belongs to. A JSON integer id becomes the string placeholder. An id
created before the test, which should not happen once the harness has emptied the tables, is
`«t_repository#prior»`. A test's starting point is each table's counter when the test begins, read
after the harness empties the tables.

**Why not literal ids, reset before each test.** That was the first design, and it changed what the
application did. A test then rebuilt the previous test's ids, and a cache keyed by a target and
stamped by its scans' count and newest id (`LicenseGovernanceService`'s tallies) served the previous
test's counts. Production never reuses an id.

The replay ranks the ids it observes the same way, by order of creation per table within the test,
and substitutes them into the requests it sends: `«t_repository#1»` in a path is whatever id the
Rust server gave the first repository it created. Seeds are inserted with ids of the replay's
choosing, ranked in seed order.

MySQL consumes an `auto_increment` value on an insert that fails or rolls back. Expect a Rust handler
that validates before it inserts, where Java inserted and rolled back, to give the next row a
different number. It keeps the same rank only if neither side created another row in between. That
is a known source of difference. Compare ranks, not numbers.

A table that ran out of its million, or whose counter could not be moved, is named in the test's
`notes` and in `recorderFailures`.

UUID keys (`t_audit_log`, `t_api_key`, `t_agent`, `t_login_attempt`…) are random. They are replaced
like everything else, below.

## Placeholders

What changes between two runs is replaced by a placeholder in `«…»`. Ordinals are **per test**: the
same value gets the same placeholder in every file of the test, numbered in the order it is first
rendered within the file (request, seed, response, effect), file after file. To compare, the replay
applies the same rules, in the same order, to what it sent and observed, and compares the results.

**Credentials are collected before anything is rendered.** The seed shows a session's hash before the
response that minted the token. Collected from:

- `Authorization` (and `Proxy-Authorization`): the credential after the scheme;
- request cookies and `Set-Cookie`: the value;
- a request header whose name contains `token`, `secret` or `key`;
- a JSON string, request or response or row, under one of these field names, case-insensitive:
  `token accessToken refreshToken sessionToken bearerToken apiKey fullKey plainKey secret clientSecret
  totpSecret webhookSecret signingSecret password newPassword currentPassword oldPassword recoveryCodes
  recoveryCode scimToken agentKey plaintext privateKey passphrase credential authToken handoffToken
  backupCodes backupCode` (the elements, for an array). Not when the value is already a stored form
  (an Argon2 hash, a sealed value);
- anything shaped like an API key, `zsk_` and 43 base64url characters;
- any 43-character base64url run with upper case, lower case and a digit in it (thirty-two random
  bytes: a session token, an agent key), outside a stored form.

`correct horse battery staple` is never a secret. It is `ApiTestBase`'s fixture passphrase, in the
source.

Then, on every string, in this order:

| rule | placeholder |
|---|---|
| an Argon2 or bcrypt hash | `«password-hash(correct horse battery staple)»`, `«password-hash(secret:N)»` when it verifies against that secret (a password sent in this test, or an API key), else `«password-hash(?)»`. A replay seeding the row hashes that value |
| a sealed value, `v2:` and base64 (`SecretCipher`) | `«sealed»` |
| the SHA-256 hex of a known secret | `«sha256(secret:N)»`. A session's `token_hash`: the replay mints a token, stores its hash and sends it |
| a known secret, longest first | `«secret:N»` |
| the first 12 characters of a known API key (its stored prefix) | `«secret:N:prefix»` |
| 64 hex digits no secret accounts for | `«sha256:N»`. A document's digest, which names it in a path; many are the same on every run, but a document holding a date is not |
| a UUID, case-insensitive | `«uuid:N»` |
| an ISO date, date-time or instant from three years back to eleven ahead | `«date»`, `«datetime»` (no zone), `«instant»` (`Z` or an offset). Outside the window it stays literal: `2020-01-01`, the year 9999 |
| an RFC 1123 date in that window | `«http-date»` |
| a compact stamp in that window, `20261016T101500Z` or `20261016-1015` | `«stamp»` |
| an identity, nine digits in a table's range (see *Identities*) | `«t_<table>#N»` |
| a run of 12 to 19 digits with no letter or digit beside it | `«n:N»`. These are `System.nanoTime()` and `currentTimeMillis()` suffixes: `ApiTestBase` names accounts `admin-<nanoTime>` |

And by field name: a row's column (an updated row's `from` and `to` count as their column's), or a JSON
field:

| field | rule |
|---|---|
| `code`, `totp`, `totpCode`, `mfaCode`, `otp` holding 6 to 8 digits | `«one-time-code»`. Derived from a random secret and the clock |
| `window_key` | `<limit>:«window»:<digest>`. `RateWindows` numbers windows from the epoch |
| `totp_last_step` (an integer) | `«clock-step»` |
| any field whose name contains `hash` and whose value is, after the rules above, 32 to 128 hex digits | `«sha256:N»`, numbered with the digests above. An audit entry's `entry_hash` and `previous_hash` keep their links: entry 2's `previous_hash` is entry 1's `«sha256:N»` |
| a JSON integer in a table's range | the string `«t_<table>#N»` |
| a JSON integer of 12 to 19 digits | the string `«n:N»` |

Placeholders do not escape anything. A value the test wrote that matches a rule, such as a fixed date
inside the window or a deterministic digest under a `hash` field, is replaced too. That loses a check
the replay could have made, but it never makes a golden unstable.

## What is not recorded

- **Classes that build no `MockMvc`**: `platform.web.ServerRefusalsTest` (a real socket, because the
  refusals it tests happen in the connector) and `access.web.security.chain.RequestBodyLimitFilterTest`
  (a unit test of the filter). Neither sends a request through the application's dispatcher.
- Context tests without HTTP (services, repositories, the architecture suite) are not traffic.
- Outbound calls the server makes, to stubs or to tests' collectors. Phase 4's goldens add stubs.

## Determinism

Two recordings of the same tree should produce identical files, with these known exceptions. They come
from the application or the harness, not from the recorder:

- `concurrent` records (rank and content);
- audit chain links when one request writes several entries in an order the application draws, such
  as revocations walked in UUID order. The entries are the same and sorted the same, but which
  `«sha256:N»` chains onto which can differ.

Anything else that differs between two recordings is a defect of the recorder or a nondeterminism of
the application, and both are worth knowing about. Compare two recordings with `diff -r`.

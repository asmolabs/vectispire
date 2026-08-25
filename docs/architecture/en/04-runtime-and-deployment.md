# 04 — Runtime and deployment

What a deployment is allowed to be, what it is refused, and what coordinates several of them.

## The two shapes

There is one binary and one switch. `VECTISPIRE_EMBEDDED_WORKER` decides whether the control
plane also scans.

| | Embedded worker (`true`, the default) | Remote agents (`false`) |
|---|---|---|
| Who holds the Docker socket | the control plane | each agent |
| Who reaches the database | the control plane | the control plane, **only** |
| Who holds `ENCRYPTION_KEY` | the control plane | the control plane, **only** |
| What an agent is given | — | a scoped token, and sealed material per scan |

**The switch is load-bearing rather than cosmetic.** `ScanDispatcher` takes an
`Optional<ScanRunner>` and declines to claim work when it is empty — a control plane with no
scanning capability must not claim a scan and then fail it. Setting the flag to `false` is what
makes that empty branch mean *"served by agents"* instead of *"nobody wired the runner"*; the
second was once true, and every queued scan stayed `pending` for ever without a single log line.

An agent never opens a JDBC connection and never holds the encryption key. It receives work by
long polling ([0003](decisions/0003-long-polling-for-agents.md)) and returns results over the same
channel.

## The database

**PostgreSQL or MySQL. MySQL is the default** — it is what `docker-compose.yml` ships — and the
engine is selected by `VECTISPIRE_DB_URL` alone
([0014](decisions/0014-two-engines-and-a-test-fixture.md)).

**SQLite is refused, and the refusal is worth stating because it used to be documented as
supported.** Under the shipped `ddl-auto: validate` the application does not start on it: SQLite
has type *affinities* rather than types, so it reports a timestamp column back as FLOAT and
Hibernate rejects the mapping. It remains in the repository as the fixture the HTTP test suite
runs on, and its migrations are maintained for that reason alone.

The schema belongs to the Flyway migrations, one native SQL set per dialect
([0013](decisions/0013-flyway-multi-dialect-migrations.md)). Hibernate validates and never
reconciles: a deployment whose schema disagrees with the entities fails at startup rather than on
the first query that touches the difference.

## Several instances at once

Four periodic jobs run in every instance, and **only one of them is leader-elected.** The
distinction is the whole of this section, because the obvious summary — "background jobs are
coordinated by a lease" — is wrong and would send a reader looking for a lease that is not there.

| Job | Period | Coordination |
|---|---|---|
| Scan worker tick | 15 s | none needed: **claiming** a queued scan is the concurrency control |
| Scan scheduler | 60 s | **leader-only**, on the `scheduler` lease in `t_leader_lease` |
| Notification relay | 60 s | none: the outbox marks what it sent |
| Hourly maintenance | 1 h | none: pruning is idempotent |

The scheduler is elected because it *creates* work: two instances deciding independently that a
nightly scan is due would queue it twice. The others either claim what already exists or repeat an
operation whose second run costs nothing — and an election there would buy nothing while adding a
lease that can expire mid-pass.

**Every job waits before its first run.** `fixedDelay` spaces out the runs that follow and does
nothing about the first, which would otherwise fire while Flyway has just finished and the pool is
still filling.

## What a deployment must be given

Two variables have no default, on purpose, and the container refuses to start without them:

- `ENCRYPTION_KEY` — decrypts every deployment SSH key and integration token the instance holds. A
  shared default would mean anyone holding a copy of this repository can read them.
- the database password, and the first administrator's password.

`VECTISPIRE_TRUSTED_PROXIES` is empty by default, which means `X-Forwarded-For` is **ignored** and
the peer address is the rate-limiting key. Set it only when something really does sit in front:
trusting the header without a proxy lets a caller choose their own rate-limit bucket.

## The audit mirror

`VECTISPIRE_AUDIT_MIRROR` is **off in the application and on in compose**, which looks
inconsistent and is not: the application ships with it off because writing to a path by default
fails on a read-only filesystem, and a compose deployment has a writable volume, so that is the
one place the default can be "on".

It closes the case the hash chain cannot see. Deleting the *last* entry — the one nothing descends
from — leaves a chain that still verifies perfectly. The mirror makes that deletion require a
second edit in a second medium, and a log collector normally ships the file off the host within
seconds. Point a collector at the volume; a mirror nobody collects only raises the cost of one
deletion.

## The images

Two are published, and the `Dockerfile` route is the one that ships: it can `chown` the audit
mirror's directory, where Jib can only set a mode. Jib builds the same two on every push because
it needs no daemon and is fast; the `Dockerfile` build runs nightly. Both carry `LICENSE` and
`NOTICE`, and the nightly job asserts the jar is where the image says it is — the defect that made
the job necessary was a `COPY` of a file the build never produced.

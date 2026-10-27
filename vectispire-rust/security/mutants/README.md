# Mutation checks

A mutation check breaks one guard of the code on purpose and expects the tests to notice. Each **mutant** is
a file, the exact text of a guard, its replacement and the `cargo test` that should turn red: if the suite
goes red the mutant is *killed*; if it stays green the mutant *survived* and a test is missing. A mutant that does not
compile proves nothing about the tests and is reported apart, never counted as killed. A mutant that hangs (a loop
whose guard was removed) is killed with its process group and counts as red.

Every file is restored after each mutant, and on SIGTERM or SIGINT; the sources are hashed before and after the
run and the run fails if they differ. A pattern that is not found exactly once is a failure of the script, not a
survived mutant. **An equivalent mutant — one no test can tell from the original, because the guard is
redundant — is removed from the list with its reason in a comment, never counted as killed.**

The mutant lists are data, one script per task; the shared logic is in `_runner.py`.

| Script | Task | Reads |
|---|---|---|
| `p1-1-accounts.py` | 1.1 accounts | `cp-access`: passwords, account rules, the service, the user store |
| `p1-2-credentials.py` | 1.2 credentials | `cp-access`: sessions, keys, agent and integration scopes |
| `p1-5-authz.py` | 1.5 authorization | `cp-access`: visibility, rows, roles, four eyes, approvers, principal resolution |
| `p1-6-audit-settings.py` | 1.6 audit, settings, platform | `cp-audit`, `cp-settings`, `cp-platform`, `cp-app`'s mirror adapter |
| `p1-merge-role.py` | Phase 1 merge | the one `Role` in `cp-http` and what reads it in `cp-access` |
| `p2-1-maintenance.py` | 2.1 maintenance, architecture rules | `cp-arch-tests`, `cp-maintenance` |
| `p2-2-outbox.py` | 2.2 outbox | `cp-outbox`: the retry policy, the stamped payload, the registry and the relay guard, the relay, the tasks, the statements on both engines |
| `p2-3-crypto.py` | 2.3 encryption | `cp-crypto`, and `seal` in `crates/crypto` |
| `p2-4-fingerprint.py` | 2.4 fingerprint, vocabulary, cron | `crates/domain` |
| `p2-5-protocol.py` | 2.5 the protocol's server half | `crates/protocol`: the Jackson reader, coercions, the result, the server's bodies, the claim's writer |
| `p2-11a-replay.py` | 2.11a golden replay | `cp-contract`'s `recorded`: the placeholders' matching, the window, the documents', headers' and rows' comparison, `deferred.txt`'s coverage |
| `p2-6-targets.py` | 2.6 targets | `cp-targets`: visibility in every service and route, a deletion's order and revocations, the identity guard, the schedule, the credentials, the forms, the readers; the principal's restriction (`cp-http`, `cp-access`), `TargetGrants`; the domain rules it reads |
| `p2-8-ingestion.py` | 2.8 ingestion | `cp-scanning`'s `ingestion`: the columns and clipping after the fingerprint, the low-confidence downgrade, the secrets' deduplication, a plugin's scope, the end-of-life conditions, the licences read per scan, the exploited flag, a `null` element refused in every list; the ingestor `cp-app` composes |
| `p2-7-scanning.py` | 2.7 scanning | `cp-scanning`: the claim's conditions, the attempts, the leader lease, the scheduler, retention, the dispatcher's sealing and refusals, the result's write, the routes' visibility; `domain`'s `schedules` and `scan_queue` |
| `p4-2a-siem-domain.py` | 4.2 SIEM, domain layer | `crates/domain`'s `siem`, `triage_status` and `Instant`'s calendar; `cp-audit`'s guards between the audit operations and the SIEM's placements and signals |

## Running

From anywhere (the workspace is resolved from the script's location). A Rust toolchain is needed, and Docker for
the mutants whose tests run on both engines.

```bash
security/mutants/p2-3-crypto.py                      # every mutant of the script
security/mutants/p2-3-crypto.py "another prefix"     # the mutants whose name contains one of the words
security/mutants/p2-3-crypto.py --list               # the mutants and their tests, nothing is run
security/mutants/p2-3-crypto.py --check              # every `old` text is found exactly once; no cargo
```

`--check` is cheap and is the one CI can run: it fails when a refactor moved or reworded a guard, before anybody
has to rerun the suite to find out. The exit status of a run is non-zero when a mutant survived, did not compile,
did not match or a source was not restored.

The mutants build in their own target directory, `target/mutants`, or the one `CARGO_TARGET_DIR` names, so that
a `cargo test` running at the same time does not rebuild for them. `p1-6-audit-settings.py` runs Java as an oracle
for the mutants that ask for the `oracle` feature and needs `ORACLE_CLASSPATH_FILE` set to the classpath file the
oracle build writes.

When a guard is added, add its mutant to the script of the task that owns it; when `--check` fails, fix the
text if the guard still exists and remove the mutant, with a comment, if it does not.

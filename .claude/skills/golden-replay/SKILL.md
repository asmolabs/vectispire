---
name: golden-replay
description: Replaying the Java suite's recorded HTTP traffic against the Rust control plane's routes — recording, measuring a module's routes before they are owed, sorting the red recordings into port defects, missing modules and irreproducible ones, and shrinking golden/deferred/ (one file per module, each with its ceiling) without weakening the check. Use when bringing ported routes to green, when the rust-replay job is red, or when asked how far a module is from Java.
---

# The golden replay

The Java suite (about 2,370 tests) runs with a recorder on and writes every request it makes, the rows it
seeded, the answer, and the rows the request changed (`crates/cp-contract/README.md` has the format). The
replay sends the same requests to the Rust router on MySQL and PostgreSQL and compares status, headers,
body (as templates: `«t_issue#1»`, `«instant»`…) and the rows changed. **It is the port's main oracle**:
most defects this port has fixed were invisible to a careful reading and red here.

`golden/deferred/` lists what is not replayed yet, and why — **one file per module whose port ends the line**
(`<module>.txt`), `_composition.txt` for what composing ends, `_recording.txt` for what the recorder or the replay
cannot reproduce (its `README.md` says which goes where). It **only shrinks**, and each file's one `ceiling N` line
holds that file's length, so two ports shrinking different modules never touch the same line;
`cp-contract replay-plan` prints the total and each file's. A request to a route that is not served is not sent: its
recorded effect is applied, so later requests of the same test see the state Java left.

**Which routes are owed is derived**, not listed: every route the replay's router composes
(`crates/cp-agents/tests/golden.rs`), but those a `route` line still covers — their recordings are played in Java's
place until the line goes. Removing the line is what makes a composed route owed.

## 1. Record and replay, as CI does

```bash
cd vectispire-rust
crates/cp-contract/scripts/record-goldens.sh <dir>   # JDK 25 + Docker; ~15 min; 2 tests fail under the recorder, no others
crates/cp-contract/scripts/replay-goldens.sh <dir>   # replay-plan, then the replay test on the engines selected
```

The engines are `VECTISPIRE_TEST_ENGINES`' (unset: both). CI's `rust-replay` on a pull request replays on
MySQL alone (`VECTISPIRE_TEST_ENGINES=mysql`); the nightly's `rust-replay` records afresh and replays on
both — PostgreSQL is the nightly's, and a recording red there only is the port's defect all the same.
That selection is not a narrowing: `VECTISPIRE_GOLDEN_ENGINES` still is, and still fails the run.

Record **at the commit you replay**: the recordings are the Java tree's, and the Rust line carries Java
fixes the base may not have. Keep `<dir>` outside the repository (the scratchpad), and re-record after a
reboot wipes it. `VECTISPIRE_GOLDEN_ONLY` and `VECTISPIRE_GOLDEN_ENGINES` narrow a run for debugging; a
narrowed run fails on purpose, because it checked less than CI does.

## 2. Measure before the routes are owed

A route counts only once it is in the served set, and then every recording of it must be green or
listed — so a module is measured first. `measure.patch` (beside this file) adds a local switch to
`crates/cp-agents/tests/golden.rs`: with `VECTISPIRE_GOLDEN_MEASURE=1` every route of the composed
modules is served and owed — those a `route` line covers too — and `VECTISPIRE_GOLDEN_OUT=<file>.tsv` writes one
line per recording of a covered route — `name \t METHOD /route \t green|differs|unreplayable \t detail`.

```bash
git -C .. apply .claude/skills/golden-replay/measure.patch  # from vectispire-rust/; never committed
CARGO_INCREMENTAL=0 VECTISPIRE_GOLDEN_MEASURE=1 VECTISPIRE_GOLDEN_OUT=$SP/m1.tsv VECTISPIRE_GOLDEN_DIR=<dir> \
  SQLX_OFFLINE=true cargo test -p vectispire-cp-agents --test golden -- --ignored --nocapture
```

The measuring run always ends red — that is the switch, not a result. A module not composed by the
replay's router yet is composed there first (`phase_three`, or the phase's own composition beside it). If the patch
no longer applies, re-create it from the description above rather than editing the real test.
Keep each run's TSV and compare two runs **by recording**, not by totals: a fix that turns 40 green can
hide two that turned red.

## 3. Sort what is red

Group the reds by route, then by the first line of their difference with digits and placeholders
stripped (`sed -E 's/[0-9]{3,}/N/g; s/«[^»]*»/X/g' | sort | uniq -c`): a handful of causes usually
explain hundreds of recordings. Each cause is one of:

- **A port defect** — the Rust answer differs from Java's for a reason in the Rust code. Fix it, with a
  unit test that fails on the old code; `port-module` §3 lists the classes already met (order of
  refusals, unaudited access denial, UTF-16 lengths, nanosecond time, Jackson's unreadable body, fixed
  messages, paging windows).
- **A Java nondeterminism** — the recording itself depends on a salted `Set` order, the clock or the
  run's uptime. Fix the Java side (an `EnumSet`, a fixed-width name) so the recording becomes stable, in
  its own commit with a test.
- **Another module missing** — a SIEM row in the outbox, a ticket reference checked against the tracker:
  leave it red until that module is ported; its route stays listed with the phase that ends it.
- **Irreproducible** — the recorder hid a value the replay would have to choose (`«window»`, a
  `new_expiry` far in the future, an ordering by hidden instants), or the test mocks a Java service.
  Such a recording gets a `golden` line naming why, **only if the list does not grow net** — it is the
  price of taking a route out, never a way to quiet one.
- **A defect of the replay itself** — e.g. a recorded `Content-Length` compared against a body whose
  hidden values change its length. Fix it in `cp-contract` with a test that would have caught it; the
  bar is that the check still refuses every real difference.
- **Timing** — a throttle window, a lease, a retry wait read from the wall clock on a slow run. Confirm
  by comparing with the previous run's TSV before calling it noise.

A schema violation is reported only when Java's own answer does not have it (the 0.11.1 document leaves
`null` out of some nullable fields); positional ones such as `/items/2/source` usually follow from a
count difference — fix the count first.

## 4. Take a route out

When every recording of a route is green in the measuring run:

1. remove its `route …` line from its module's file, `golden/deferred/<module>.txt`, and lower that file's
   `ceiling` by as many lines as left, in the same commit (a file left with no line is deleted) — nothing else: the
   route is owed because the line is gone;
2. revert the measuring patch (`git checkout -- crates/cp-agents/tests/golden.rs`, then re-apply your
   real edit) and run the replay with no measuring variable **and on both engines** (`VECTISPIRE_TEST_ENGINES` unset)
   before committing — the pull request's job only replays on MySQL, and a route leaving the list on a
   PostgreSQL red would first be seen by the nightly. A route green under measurement can still be red when its neighbours are not served:
   effects are then applied from the recording rather than produced.

**Never edit `golden/deferred/` to make a run pass.** A line whose recordings all replay green, or that no
recording needs, fails the replay — the list cannot rot in the other direction either.

## 5. When CI's `rust-replay` is red

Read which recordings and why from the job log (`gh api --allow-escape-sequences
repos/asmolabs/vectispire/actions/jobs/<id>/logs`, escape codes stripped), reproduce locally with a
recording made at the same commit, and sort as in §3. A red that appears without a Rust change is
usually the Java side: a test added or changed under `vectispire-java/` records new traffic.

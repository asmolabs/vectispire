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

The mutant lists are data, one script per task (`p<phase>-<task>-<what>.py`); the shared logic is in `_runner.py`.
**There is no table of the scripts here**: each says on its first line which task it checks and what it reads, and

```bash
for script in security/mutants/p*.py; do sed -n 2p "$script"; done
```

lists them. A table every port appended a row to was a line two ports running at once both edited; `check.sh` runs
every `p*.py --check`, so a new script needs no line anywhere to be checked.

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

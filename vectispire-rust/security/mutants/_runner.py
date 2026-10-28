"""The runner every mutation script of this directory shares; each script keeps only its mutants, as data.

A mutant is `(name, path, old, new, tests)` (a seventh element, `followups`, is optional):

- `path` is relative to the workspace (`vectispire-rust/`), `old` is the text of the guard exactly as it stands
  and must occur exactly once in that file, `new` is what replaces it;
- `tests` is the arguments of one `cargo test` (without `cargo test --locked`), or a list of such lists run in
  turn, the first red one killing the mutant;
- `followups` is a list of `(old, new)` pairs applied to the mutated text afterwards, for a guard whose closing
  has to change with its opening; each must occur exactly once in the mutated text.

A mutant counts as killed only when a test goes red. One that does not compile proves nothing about the tests and
is reported apart, never counted as killed; one that hangs is killed with its whole process group (killing cargo
alone leaves the test binary running) and counts as red, since a guard removed from a loop turns a wait into a
hang. A pattern that does not occur exactly once is a failure of the script, not a survived mutant. Every source
is restored in `finally` and on SIGTERM/SIGINT, and hashed before and after the run.

Command line: no argument runs every mutant; words select the mutants whose name contains one of them; `--list`
prints the mutants and runs nothing; `--check` only verifies that every `old` is found exactly once (no cargo, so
cheap enough for CI). The target directory comes from CARGO_TARGET_DIR, else `target/mutants` under the workspace
(a build of its own, so that a concurrent `cargo test` does not rebuild for the mutants).
"""
import hashlib
import os
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _runs(tests):
    return tests if tests and isinstance(tests[0], list) else [tests]


def _read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


def _write(path, text):
    with open(os.path.join(ROOT, path), "w", encoding="utf-8") as f:
        f.write(text)


def _digest(paths):
    h = hashlib.sha256()
    for path in paths:
        h.update(path.encode())
        with open(os.path.join(ROOT, path), "rb") as f:
            h.update(f.read())
    return h.hexdigest()


def _mutated(original, mutant):
    _, _, old, new, _, *rest = mutant
    text = original.replace(old, new)
    for follow_old, follow_new in (rest[0] if rest else []):
        if text.count(follow_old) != 1:
            return None
        text = text.replace(follow_old, follow_new, 1)
    return text


def _check(mutants):
    bad = 0
    for mutant in mutants:
        name, path, old = mutant[:3]
        found = _read(path).count(old)
        if found == 1 and _mutated(_read(path), mutant) is None:
            found = -1
        if found != 1:
            bad += 1
            print(f"PATTERN x{found}  {name}  ({path})")
    print(f"{len(mutants) - bad} of {len(mutants)} mutants match the sources")
    return 1 if bad else 0


def _run_tests(tests, env, timeout):
    """'red', 'compile', 'hung' or 'green'."""
    for args in _runs(tests):
        process = subprocess.Popen(["cargo", "test", "--locked", *args], cwd=ROOT, env=env, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            return "hung"
        if process.returncode != 0:
            if "error[E" in stderr or "could not compile" in stderr:
                print(stderr[-2000:], flush=True)
                return "compile"
            return "red"
    return "green"


def main(mutants, *, timeout=600, env=None, description=""):
    args = sys.argv[1:]
    if "-h" in args or "--help" in args:
        print(description or __doc__)
        return 0
    flags = {a for a in args if a.startswith("--")}
    words = [a for a in args if not a.startswith("--")]
    mutants = [m for m in mutants if not words or any(w in m[0] for w in words)]
    if "--list" in flags:
        for index, mutant in enumerate(mutants, 1):
            runs = " ; ".join(" ".join(r) for r in _runs(mutant[4]))
            print(f"{index:3}  {mutant[0]}  [{mutant[1]}]  cargo test {runs}")
        print(f"{len(mutants)} mutants")
        return 0
    if "--check" in flags:
        return _check(mutants)

    environment = dict(os.environ, **(env or {}))
    environment.setdefault("CARGO_TARGET_DIR", os.path.join(ROOT, "target", "mutants"))
    sources = sorted({m[1] for m in mutants})
    before = _digest(sources)
    originals = {}

    def restore(signum=None, frame=None):
        for path, text in originals.items():
            _write(path, text)
        originals.clear()
        if signum is not None:
            sys.exit(1)

    signal.signal(signal.SIGTERM, restore)
    signal.signal(signal.SIGINT, restore)
    killed, survived, uncompiled, mismatched = [], [], [], []
    try:
        for mutant in mutants:
            name, path = mutant[:2]
            original = _read(path)
            mutated = _mutated(original, mutant) if original.count(mutant[2]) == 1 else None
            if mutated is None:
                print(f"!! {name}: pattern not found exactly once", flush=True)
                mismatched.append(name)
                continue
            originals[path] = original
            started = time.time()
            try:
                _write(path, mutated)
                outcome = _run_tests(mutant[4], environment, timeout)
            finally:
                _write(path, original)
                del originals[path]
            if outcome == "compile":
                uncompiled.append(name)
            elif outcome == "green":
                survived.append(name)
            else:
                killed.append(name)
            label = {"red": "killed", "hung": "killed (hung)", "green": "SURVIVED", "compile": "DID NOT COMPILE"}
            print(f"{label[outcome]:16} {name} ({time.time() - started:.0f}s)", flush=True)
    finally:
        restore()
    after = _digest(sources)
    print(f"{len(killed)} killed, {len(survived)} survived {survived}, not compiled {uncompiled}, "
          f"pattern mismatches {mismatched}; sources restored identical: {before == after}")
    return 0 if before == after and not (survived or uncompiled or mismatched) else 1

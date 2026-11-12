# The Java suite's recordings not replayed yet, and why

Read by `crates/cp-contract/src/recorded/deferred.rs` (the format) and `src/shrinking.rs` (the files and their
ceilings): `cp-contract replay-plan` holds every recording of a route not served to it, and the golden replay
(`crates/cp-agents/tests/golden.rs`) every recording of a served one.

```text
route METHOD /template | reason      every recording of an operation of the contract
golden class/file      | reason      one recording of a route the Rust router serves
outside METHOD /path   | reason      a request no operation of the contract answers
```

**One file per module whose port ends its lines**, so that two ports running at once never edit the same file:

| File | Holds |
|---|---|
| `<module>.txt` | the module's routes not served yet (`route`), and the stand-ins for it that the served routes' recordings meet (`golden`, `outside`), each reason naming the module and its phase |
| `_composition.txt` | what composing ends rather than a port: the binary's own answers outside the contract (task 2.11), and the ingestion the replay composes as a stand-in |
| `_recording.txt` | what the recording or the replay cannot reproduce yet, whichever module serves the route: a value the recorder hides, a state the test changes behind the HTTP API, a request this replay does not send |

**This list only shrinks.** Each file starts with `ceiling N`, N its number of lines: a file above its ceiling grew, a
file below it was not lowered in the commit that removed lines, and both fail, as does a file that lists nothing (it is
deleted). A line no recording needs, or whose recordings all replay green, fails the replay. A line is one line of the
whole list: the same line in two files is listed twice. Never edited to make a check pass: a recording that differs
from Java is a defect to fix, or a stand-in named here with the task that ends it.

A `route` line on a route a module serves keeps that route out of the golden replay — its recordings are played in
Java's place — until the line is removed, in the commit that makes them replay green: removing it is what makes the
route owed.

`cp-contract replay-plan <dir>` prints the total and each file's count.

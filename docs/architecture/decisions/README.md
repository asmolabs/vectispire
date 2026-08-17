# Decision register

One page per structural decision: what was decided, what was rejected, and what it costs.
These are the choices you would regret having to re-argue, or would get wrong again by not
knowing the alternative already tried.

| # | Decision | Date | Status |
|---|---|---|---|
| [0001](0001-pluggable-scan-layer.md) | The scan layer is pluggable behind `ScannerEngine` | 2026-07-28 | **superseded by [0010](0010-one-scan-runner.md)** |
| [0002](0002-the-database-carries-the-queue.md) | The database carries the queue, not a broker | 2026-08-06 | accepted |
| [0003](0003-long-polling-for-agents.md) | Agents speak HTTP long-polling, never to the database | 2026-08-06 | accepted |
| [0004](0004-sqlite-and-postgresql-only.md) | Two database engines: SQLite and PostgreSQL | 2026-08-10 | **superseded by [0008](0008-postgresql-and-mysql.md)** |
| [0005](0005-quality-never-blocks-the-gate.md) | Quality and AI review enter no verdict | 2026-08-07 | accepted |
| [0006](0006-semgrep-rules-written-here.md) | The Semgrep rules are written here, not redistributed | 2026-08-07 | accepted |
| [0007](0007-none-is-not-an-empty-list.md) | An analyzer that fails returns `None`, never `[]` | 2026-08-07 | accepted |
| [0008](0008-postgresql-and-mysql.md) | Two database engines: PostgreSQL and MySQL | 2026-08-14 | **superseded by [0009](0009-four-engines.md)** |
| [0009](0009-four-engines.md) | Four database engines, each one measured | 2026-08-16 | accepted |
| [0010](0010-one-scan-runner.md) | One scan runner, and the agent is the seam | 2026-08-17 | accepted |

## The register's rules

**A decision is immutable.** It describes what was decided on a date, with what was known
then. When it no longer holds, a new one is written that supersedes and cites it, and the
old one moves to *superseded* status — without its text changing.

That is precisely what the two old `ADR-001` and `ADR-002` files failed to do: they were
amended section after section until nobody reading them could say what was still true.

**What has no alternative is not a decision.** Using an ORM to talk to a database does not
get a page here. A decision earns the register when somebody could have chosen otherwise,
and would choose otherwise again without knowing why.

**The rejected alternative is the half that counts.** A reader who does not find the
alternative will assume it was never considered, and will propose it. The "what was
rejected" section is not politeness: it is what stops the argument from starting over.

## A note on the port

Decisions 0001 to 0007 were written against the Python/Reflex implementation. Their
reasoning still holds — that is why they are here — but two of them named artifacts the
NestJS port did not carry over. 0001's contract test and its two non-Docker engines are
settled: [0010](0010-one-scan-runner.md) supersedes it and abandons the seam rather than
rebuilding it. 0006's fetch script is still missing with no superseding page, and carries a
dated note after its text, outside the decision, rather than an edit to the decision
itself.

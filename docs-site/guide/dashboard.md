# Dashboard

The navigation is grouped in two, and the split is a statement about what each half can do
to a build.

**Security** holds the gate verdict per target, the issue backlog, repositories and
containers. Anything here can fail a build.

**Quality** ranks the code-quality backlog by rule, file and repository, and says plainly
that none of it can fail a build. See [Code quality](quality.md).

## The security overview

Per target: the gate verdict, the standing backlog by severity, and when it was last
scanned. The verdict has been computed since gate policies existed; this screen is where it
is finally shown.

Two states are named here that appear nowhere else: a target **never scanned**, and one
whose **last scan failed**. Both carry an empty backlog, and an empty backlog passes every
policy. A dashboard that only showed the numbers would show these two as green.

## Backlog over time

The figures above are snapshots. They answer "how much" and never "better or worse than
last month". The series answers that: standing backlog day by day, what appeared against
what was resolved, and the mean time to resolve.

MTTR is shown **absent** rather than zero for a period in which nothing was resolved. Zero
would read as "fixed the day it appeared", which is the opposite of what happened.

The series is narrowed by your visibility like every other view — see
[Users and teams](../administration/users-and-teams.md).

## Security posture grade

Repositories carry a posture grade and a set of recommendations, alongside their business
criticality tier. The tier is what you set when registering the repository; the grade is
computed from the backlog. A Tier 1 service at a poor grade is the first line to read on
this page.

A repository can also expose a **dynamic badge for its README**, which is how the grade
gets in front of the people committing to it rather than only the people reading this
dashboard.

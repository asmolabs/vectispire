# Tracker tickets

Vectispire opens tickets in **GitLab** or **Jira** — one per problem that would fail a
build.

## One threshold, defined once

Ticket creation uses **the same gate policy** as the CI gate.

That is the design decision worth understanding. A separate ticketing threshold would mean
two bars to keep in step, and they would drift: teams would end up with tickets for things
that do not fail their build, or a red build with no ticket behind it. One policy, one
answer. See [Gate policies](../administration/gate-policies.md).

## No duplicates, ever

The tracker reference is kept **on the issue**.

So a tracker outage is retried rather than lost, and the retry finds the existing reference
and does not open a second ticket. The same issue seen on fifty consecutive nightly scans
is one ticket.

## Configuring

Under [Settings](../administration/settings.md): the tracker type, its URL, the project or
target, and a token.

Give the token the narrowest scope that can create and read issues in the target project.
It is stored encrypted with your `ENCRYPTION_KEY`, and storing it is refused before that
key exists.

## What lands in the ticket

Enough to act without opening Vectispire: the component and version, the identifier, the
severity, whether a fix exists, EPSS and KEV status, and a link back to the issue.

## Closing the loop

Closing the ticket in the tracker does not resolve the issue in Vectispire — `state` is
written only by the pipeline, from what the scanners observe. Fix the dependency, and the
next scan resolves it.

If it is not going to be fixed, that is a [triage decision](../guide/issues.md), with a
justification and preferably a review date.

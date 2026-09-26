# Agents

A scan is executed by an **agent**. There are two kinds, and both are rows in the same
table, listed together on the **Agents** page.

**The built-in agent** is the web process itself. Created automatically at startup, with no
configuration — which is why a single-machine install works out of the box.

**Remote agents** are separate worker processes on other machines, speaking a short
protocol: `hello`, `sealing-key` (for a `delegated` agent), `jobs`, `rules`, `heartbeat`, `result`.

Two durations cross it, in two different forms, for anyone writing a client against the
published contract. `GET /api/v1/agent/jobs?wait=30` takes the long-poll wait as **whole
seconds** — 0 by default, which answers at once, and held for at most 30. The result's `duration`
is **ISO-8601 text** (`"PT12.345S"`), the `format: duration` the contract declares; a number of
seconds from an older agent is still accepted. In the result, `[]` means a step ran and found
nothing, and `null` or a missing field means it did not run — which is why the difference matters:
only the first resolves that step's backlog.

Both run the same code and both send back the scanners' raw output for the control plane to
normalise. A result produced on another machine is therefore **indistinguishable** from a
local one: same rows, same enrichment, same license policy, same reconciliation.

## When to add one

- Keep the Docker socket off the host that serves the interface.
- Reach a repository or registry only routable from another network segment.
- Add capacity.

## Running one

```bash
# On the agent's machine — the key comes from /agents, shown once
VECTISPIRE_URL=https://vectispire.internal \
VECTISPIRE_AGENT_TOKEN=zsk_... \
java -jar vectispire-agent.jar      # built by ./gradlew :vectispire-agent:bootJar, JDK 25
```

Or as a container, which is how it is meant to be deployed:

```bash
docker compose --profile with-agent up -d
```

An agent **polls over HTTP**, so it needs no inbound port. Its key carries the `agent`
scope and **no database access** — that is a security property rather than a detail. An
agent with a database connection would also need `ENCRYPTION_KEY`, which is the ability to
decrypt every deploy key Vectispire holds.

In the shipped composition the agent reaches only the API and a daemon proxy of its own; the
database and the control plane's proxy are on networks it is not attached to. That keeps it from
*asking* for the key — it does not make one host two: both proxies reach the same daemon, and
daemon access is root there. The profile is for evaluating the protocol. For the isolation, run
the agent on another machine and set `VECTISPIRE_EMBEDDED_WORKER=false` on the control plane.

## Running several scans at once

**Concurrent scans** (`max_concurrent`) is how many scans one agent runs in parallel: **from 1 to
16**, 1 when nothing is said. Set it when you declare the agent, or later with the sliders icon on
its row — or `PATCH /api/v1/admin/agents/{id}` with `{"max_concurrent": 4}`. A value outside 1–16
is refused with a 400 rather than quietly rounded. The row shows it as *running / allowed*, and a
change is written to the audit log.

It is enforced on both sides. The control plane hands an agent a new scan only while the scans it
holds — claimed, not yet reported, lease still live — are fewer than the limit, and it counts them
in the database, so two polls of the same agent cannot take it past the limit together. The agent
stops polling as soon as it is full.

**The limit belongs to the agent's row, not to a process.** Two processes started with the same key
share one limit between them — and, in `delegated` mode, only the one that announced itself last can
open a sealed key. For more machines, declare more agents.

### Sizing it

Each scan runs up to five scanner containers one after the other, each capped at 2 GB of memory and
at all but one of the Docker host's cores, and the vulnerability matcher downloads its database —
about 2 GB — into that scan's own workspace. Per concurrent scan, count roughly:

| | per scan |
|---|---|
| CPU | one core |
| Memory | 2 GB, on top of the agent's own JVM |
| Disk (temporary directory) | 3 GB — the clone, the SBOM and the vulnerability database |

Scans past what the machine can hold do not wait their turn: they compete for the same cores and
time out together, 15 minutes per scanner. Stay below the machine; more capacity is another agent.

### Changing it, and stopping an agent

**A lowered limit applies to the next claim.** No new scan starts until the running ones fall below
it, and nothing running is interrupted. The agent learns the new value from the answer to its next
poll — raised or lowered, without a restart.

**Stopping an agent waits for its scans.** On `SIGTERM` — `docker stop`, a rolling update — it stops
claiming and waits for the scans in progress to be handed back. Abandoning them would cost more
than waiting: the protocol has no call to give a scan back, so an abandoned scan keeps its lease
until it lapses (20 minutes after its last heartbeat), then returns to the queue having used one of
its three attempts, and its work is lost. Give the container a grace period as long as your longest
scan — `stop_grace_period: 30m` in compose; Docker's default is 10 seconds.

If the process is killed first — or the machine dies — that lapse is exactly what happens. Until
then its scans still count against its limit, so an agent restarted at once claims only what is
left; once they lapse they no longer count, even before the queue puts them back.

## Credentials modes

| Mode | What the controller sends | When |
|---|---|---|
| `local` (default) | nothing | the agent's machine has its own git access — over SSH: a private repository over HTTPS cannot be cloned in this mode. A compromised agent yields only what that machine was granted. |
| `delegated` | the deploy key or HTTPS token, per job | a trusted machine only. |

In `delegated` mode the key or token **only ever leaves sealed** for the agent's own process, and
never in the clear — over HTTPS or not. It is never written to disk on the agent — it is parsed in
memory and handed to the transport — and every delivery is audited.

### Before delegating credentials: pin the signing key {#before-delegating-credentials-pin-the-signing-key}

**A delegated agent receives nothing until a result-signing key is pinned for it** — see
[Attesting an agent's results](#attesting-an-agents-results) — and its private half is in the
agent's configuration. The reason is where the sealing key comes from. The agent makes a fresh
X25519 pair at every start and announces the public half; the control plane seals credentials for
it. That announcement crosses the same network path as the credentials, so a TLS-terminating proxy
on that path could otherwise change it. The agent therefore **signs its sealing key with its pinned
signing key**, and the control plane accepts only a sealing key whose signature verifies against the
key an administrator pinned ([decision 0031](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0031-a-sealing-key-is-believed-only-on-the-pinned-key.md)).
**Sealing takes a TLS-terminating proxy out of the trust boundary, given a pinned signing key.**

So, for each `delegated` agent:

1. Pin a signing key on its row (the lock icon on `/agents`), and set the private half shown once as
   `VECTISPIRE_AGENT_SIGNING_KEY` in the agent's configuration.
2. Run an agent of this version and restart it. After its `hello` it announces its sealing key,
   signed; the log says `Sealing key verified by the control plane`.
3. The row now reads *Sealed end to end*. Until then it reads *No verified sealing key: credentials
   withheld*, and every claim of a scan that needs a key or token is answered **412** with the step
   that is missing — the scan goes back to the queue, nothing is sent. Image scans, which need no
   credential, run meanwhile.

**Rotation is automatic.** Each start makes a new pair, stamped with its creation time; the control
plane keeps the newest key signed with the pinned key and refuses an older one (**409**, audited).
A `hello` without a key, or with one nobody signed, never replaces or clears the accepted key.

**Resetting it is an administrator's act.** `DELETE /api/v1/admin/agents/{id}/sealing-key` forgets
the key — for an agent host whose clock went back, so that its new keys all read as older, or one
suspected of having leaked. Pinning, replacing or removing the signing key forgets it too. Both are
audited, and the agent announces a new key at its next start, or at its next claim.

A signature that does not verify is refused with **403**, written to the audit log as
`AGENT_SEALING_KEY_REFUSED` and sent to the SIEM as `ZAN-SEC-020`: the agent's configured key is not
the pinned one, or the key was not made by the agent.

**Upgrading.** An agent older than this version cannot sign its key: a current control plane hands
it no delegated credential (412, in the agent's log) while its `hello`, `local` mode and image scans
keep working. An agent of this version talking to an older control plane still works as before —
its `hello` carries the unsigned key that control plane seals for.

Prefer `local`. It bounds the damage a compromised agent can do to that machine's own
access, which is the entire reason for running scans on a separate host in the first place.

## Attesting an agent's results

**This is the one control worth turning on before the others.** Handing back a scan result is the
heaviest operation in the product: artifacts that are present and empty mean "analysed, found
nothing", which resolves the target's whole backlog of that type — silently, and correctly. So
whoever can post a result can make a target's vulnerabilities disappear from every screen, every
export and every gate verdict, leaving a scan that looks like it ran.

Until a key is pinned, the only thing standing between that and a stolen `VECTISPIRE_AGENT_TOKEN`
is the token itself — and a token lives in a compose file, an environment variable and a CI secret
store, and travels on every poll.

On `/agents`, the lock icon on an agent's row pins a key. The control plane generates an Ed25519
pair, keeps the public half on the agent's row and shows you the private half **once**:

```bash
VECTISPIRE_AGENT_SIGNING_KEY=<the value shown once>
```

Put it in the agent's configuration and restart it. Until it has the key, its results are refused
with 403 and the refusal is written to the audit log as `AGENT_RESULT_REFUSED`.

Prefer generating the pair yourself if you would rather the private half never existed here at all:
`PUT /api/v1/admin/agents/{id}/signing-key` accepts a base64 public key instead of the word
`generate`.

**The key is never one the agent announces**, and that asymmetry with the sealing key is the whole
point. A signature verified against a key its signer published on the same channel proves only what
the bearer token already proved. This one has to arrive from somebody who is not the agent.

The same key vouches for the agent's sealing key, which is why a `delegated` agent receives no
credential without it — see [Before delegating credentials](#before-delegating-credentials-pin-the-signing-key).

The row says which state each agent is in — *Results attested* or *Results unsigned* — because an
operator who believes their fleet is attested has no other way to find out it is not.

## Disabling the built-in agent

That is how you say "run nothing here". Queued scans then wait for a remote agent instead
of quietly using the web instance.

Worth doing on any deployment where the interface host should not have a Docker socket at
all.

## Pinning a target to an agent

Set **Required agent** on the repository or image. Use it for targets only routable from
one segment — not as a load-balancing tool, since a pinned target stops being scanned when
that one agent is down.

## Reading the page

Each agent shows its running scans against its limit — see
[Running several scans at once](#running-several-scans-at-once) — and when it last announced itself. An agent
that has **never announced** has not reached the control plane at all: check the URL, the
token, and that outbound HTTPS is allowed.

![The registered agents: the built-in one on local keys, a remote agent sealed and attesting its results, and a third delegated in the clear, unsigned and silent since 12:41.](../assets/screens/en/agents.png)

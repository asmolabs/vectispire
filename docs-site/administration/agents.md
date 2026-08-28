# Agents

A scan is executed by an **agent**. There are two kinds, and both are rows in the same
table, listed together on the **Agents** page.

**The built-in agent** is the web process itself. Created automatically at startup, with no
configuration — which is why a single-machine install works out of the box.

**Remote agents** are separate worker processes on other machines, speaking a four-route
protocol: `hello`, `jobs`, `heartbeat`, `result`.

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
node dist/agent/main.js
```

Or as a container, which is how it is meant to be deployed:

```bash
docker compose --profile with-agent up -d
```

An agent **polls over HTTP**, so it needs no inbound port. Its key carries the `agent`
scope and **no database access** — that is a security property rather than a detail. An
agent with a database connection would also need `ENCRYPTION_KEY`, which is the ability to
decrypt every deploy key Vectispire holds.

## Credentials modes

| Mode | What the controller sends | When |
|---|---|---|
| `local` (default) | nothing | the agent's machine has its own git access. A compromised agent yields only what that machine was granted. |
| `delegated` | the deploy key, per job | a trusted machine only. |

`delegated` **requires HTTPS and is refused without it**. The key is never written to disk
beyond a `0600` temporary file, and every delivery is audited.

Prefer `local`. It bounds the damage a compromised agent can do to that machine's own
access, which is the entire reason for running scans on a separate host in the first place.

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

Each agent shows its concurrent scan capacity and when it last announced itself. An agent
that has **never announced** has not reached the control plane at all: check the URL, the
token, and that outbound HTTPS is allowed.

# 0018 — The Docker socket is never mounted into the control plane

**Date:** 2026-09-08 · **Status:** accepted · **Decider:** Laurent Boucher

## Context

The shipped `docker-compose.yml` mounted `/var/run/docker.sock` into the control plane, and
`VECTISPIRE_EMBEDDED_WORKER` defaults to `true`, so that was the deployment everyone got.

**The Docker daemon's API has no notion of partial privilege.** Whoever reaches it can create a
container with `HostConfig.Binds: ["/:/host"]` and read or write the host's filesystem as root. No
capability is required, `no-new-privileges` does not apply, and none of the confinement
`ContainerRunner` builds — `cap_drop: ALL`, read-only root, `noexec` scratch, network cut — is
relevant, because that confinement protects the host *from the scanner*, not from the process
holding the socket.

**And the process holding the socket is the one holding everything else.** The control plane has
`ENCRYPTION_KEY` in its environment — the key that decrypts every deployment SSH key and every
integration token in the estate — plus the database credentials. Root on that host is the whole
estate.

**This is the concentration the architecture had already taken apart.**
[0003](0003-long-polling-for-agents.md) exists so that scan execution and the encryption key are
never in the same place, and `vectispire-agent` cannot compile against a JDBC driver — a property
of the build graph rather than a rule somebody enforces. The compose file put them back together.

[0017](0017-custom-checks-as-container-images.md) refuses uploaded JARs and gives the reason in
these words: a plugin "gets what the process has: the connection pool, the key that encrypts
deployment keys and tracker tokens, the Docker socket". That reasoning is correct, and it applies
unchanged to the process itself. Five third-party images — Syft, Grype, Gitleaks, Checkov, Semgrep
— are pulled and run by that daemon on input nobody controls.

### Why not simply refuse to run containers here

Because that is what the remote agent is, and it is already the recommendation. What was missing is
that the *default* deployment contradicted it, and that a single-host installation — which is a
legitimate way to run Vectispire — had no middle ground between "socket mounted" and "no scanning".

## Decision

**No Vectispire container mounts `/var/run/docker.sock`.** A `docker-proxy` service does, read-only,
and the control plane and the agent reach the daemon through it over `DOCKER_HOST`. That proxy sits
on an `internal: true` network shared with those two services and nothing else, so it is neither
reachable from the rest of the composition nor able to call out.

`ContainerRunner` needed no change: it already honours `DOCKER_HOST` and `VECTISPIRE_DOCKER_HOST`
ahead of any socket autodetection.

The proxy is pinned by the digest of its multi-architecture index, like the scanner images, and for
the same reason: a container that talks to the daemon is not somewhere a mutable tag belongs.

### What is allowed through, and it is the list of what Vectispire calls

`PING`, `VERSION`, `INFO`, `CONTAINERS`, `IMAGES`, `POST`. Everything else is refused, and the ones
that matter are named explicitly in the compose file rather than left to the default: `EXEC`,
`SECRETS`, `VOLUMES`, `NETWORKS`, `SWARM`, `BUILD`, `COMMIT`, `SYSTEM`.

**Measured against a running proxy rather than read off the documentation**, because one of these
does not behave the way the variable's name suggests:

```
GET  /_ping /version /info /containers/json /images/json   → 200
GET  /secrets /volumes /networks /swarm /system/df         → 403
POST /containers/{id}/exec                                 → 201   ← allowed
POST /exec/{id}/start                                      → 403   ← and inert
POST /containers/create  {"Binds":["/:/host"]}             → 201
```

`EXEC=0` governs the `/exec/*` endpoints, not the `/containers/{id}/exec` that creates the
instance — that path is matched by `CONTAINERS`. So an exec instance can be **created** and can
never be **started**: the capability is closed, but not where the variable's name puts it. Worth
knowing before someone reads a 201 in a log and concludes the allowlist is not applied.

## What this does not do, stated rather than implied

**It does not make the daemon safe to reach.** `POST /containers/create` is on the allowed list,
because it is the call Vectispire exists to make, and it accepts `Binds`. An attacker who achieves
code execution inside the control plane can still ask the proxy to create a container that mounts
the host. **The proxy narrows the API surface; it does not draw a boundary.**

That last line is not a deduction: `POST /containers/create` with `Binds: ["/:/host"]` was sent
through the proxy and answered 201.

What it does buy is real and worth having: the socket file is gone from the container's filesystem,
so a path-traversal or a file-write primitive no longer reaches it; an `exec` into the running
control plane or database container cannot be started; secrets, volumes and networks are refused;
and the allowlist is a written, reviewable statement of what this system asks of a daemon, which is
something no deployment had before.

**The boundary is a second machine.** An estate that needs one runs the remote agent with
`VECTISPIRE_EMBEDDED_WORKER=false` on the control plane. Then the host that can be made to run
containers is not the host that holds `ENCRYPTION_KEY`, and that is a property no proxy
configuration can provide. The documentation says so at the point where an operator chooses.

## Consequences

- `group_add: docker` disappears from the composition. It was a host-specific value — a group name
  on some hosts, a numeric GID on others — that every operator had to discover.
- One more container in the default composition, and one more image to keep current.
- An operator running Vectispire outside compose, straight against a daemon, is unchanged: nothing
  here forbids it, and `DOCKER_HOST` is the same knob.
- The claim in [`04_infrastructure_view`](../../bflorat/en/04_infrastructure_view.md) that "only the
  control plane interacts with the Docker daemon via the host socket" is now false in the letter
  and true in the spirit, and has been rewritten.

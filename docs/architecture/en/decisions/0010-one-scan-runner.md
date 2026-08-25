# 0010 — One scan runner, and no seam around it

**Date:** 2026-08-17 · **Status:** accepted

## Context

The NestJS design this replaces had a `ScannerEngine` interface with three implementations: Docker,
a local-binary mode, and a remote mode. The port carried over one of them. The other two were not
dropped for lack of time — they had stopped making sense:

* the **local-binary** mode ran scanners on the control plane's own host, with the host's
  filesystem and no capability drop, which is the opposite of what
  [`ContainerRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRunner.java)
  exists to provide;
* the **remote** mode duplicated, badly, what a remote agent does properly — an agent moves the
  *whole* runner to another machine rather than proxying one scanner call at a time.

That left an interface with one implementation, which is the shape that invites a second one to be
invented rather than needed.

## Decision

One concrete `ScanRunner`, which runs containers. The interface is not kept "for later".

**Execution moves by running an agent elsewhere, not by implementing another engine.** That is the
seam, and it is a deployment decision rather than a code one.

## Consequences

**An interface with one implementation is a claim nobody checks.** It asks every reader to hold a
generality that never pays, and it makes the concrete class harder to read: the Docker specifics —
`cap_drop`, the read-only root, the tmpfs, the network cut, the digest pin — are the interesting
part, and they cannot be expressed through an abstraction that pretends they might not apply.

**What this costs.** Running a scanner outside a container becomes a change to `ScanRunner` rather
than a new class. That is the intended friction: the container is where the isolation lives, and
somebody removing it should have to edit the file that says so.

**This decision has been used as a precedent, and that is a load it should bear.**
[0015](0015-one-secrets-engine.md) removed a second secrets engine on exactly this reasoning — a
seam with one real implementation and no coverage. Deciding that consistently is the point of
having recorded this at all.

**When to revisit.** When a second implementation is actually required by something concrete — not
when one is imagined. A registry of scanner engines, each with its own argument template and rule
file, is a different decision from re-adding an interface, and it should supersede this record
rather than slip in beneath it.

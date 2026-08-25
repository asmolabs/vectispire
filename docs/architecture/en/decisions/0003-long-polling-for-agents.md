# 0003 — Agents speak HTTP long-polling, never to the database

**Date:** 2026-08-06 · **Status:** accepted

## Context

Executing scans on remote nodes required a transport that does not extend the control plane's
trust to the machine running the scanner. A remote agent sits on somebody else's network by
definition: it is the component most likely to be compromised, and the least likely to be noticed
when it is.

## Decision

Agents poll `GET /api/v1/agents/jobs?wait=30` over outbound HTTP. Nothing listens on the agent —
`web-application-type: none`, so it opens no port — and redirects are refused, because the control
plane's address is configuration and a redirect would send a claim, an API key or a scan result to
a host nobody declared.

## What the agent holds, precisely

The short version — "the agent holds no credentials" — is wrong, and an assessor who discovers
that unaided is right to discount everything around it. The accurate boundary has three parts:

**No database.** Enforced by the module graph rather than by convention: `vectispire-agent` does
not depend on `vectispire-core`, so no JDBC driver, no Hibernate and no Spring Data is on its
compile classpath. Reaching the database does not fail review, it fails to compile.
`AgentIsolationTest` restates it and asserts the class import is non-empty first, so a renamed
package cannot silently empty the rule.

**No `ENCRYPTION_KEY`.** Nothing in the agent module reads it. This is the property that justifies
the agent's existence: that key decrypts *every* deployment key and integration token the platform
holds, and an agent holding it would turn one compromised worker into the loss of all of them.

**Deployment keys, but only sealed to itself, and only in one mode.** An agent declared
[`CredentialsMode.LOCAL`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/agents/CredentialsMode.java)
— the default and the recommendation — uses its own git access and receives nothing. An agent
declared `DELEGATED` receives a repository's private key with each task, inside a
[`SealedEnvelope`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/crypto/SealedEnvelope.java):
X25519 to the public key the agent announced at enrolment, HKDF, then AES-256-GCM. The control
plane cannot seal for an agent that never announced one, and every send is audited — that is the
condition on which the mode exists.

The agent refuses an envelope it cannot open rather than passing the ciphertext on to git. That
matters more than it looks: a sealed string handed to git is a key that fails, and the failure
reads as a permissions or repository problem, somewhere else, much later.

**An unknown mode is read as `LOCAL`.** Never as `DELEGATED`: the safe reading of "I do not know
what this agent is allowed" is "not the key".

## Consequences

The mode is the *only* thing that decides whether a key is sent. The NestJS dispatcher this
replaces consulted the transport instead, so an agent placed on a less protected machine on the
written promise that no key would reach it received the decrypted deployment key of every
repository whose scan it claimed — and nothing routed the queue, so it could harvest them all.
That is the defect this decision is shaped around, and why the check lives on the mode rather than
on anything observable about the connection.

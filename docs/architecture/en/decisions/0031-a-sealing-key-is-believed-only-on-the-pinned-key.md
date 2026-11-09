# 0031 — An agent's sealing key is believed only on the word of its pinned signing key

**Date:** 2026-09-26 · **Status:** accepted · **Amends:** [0003](0003-long-polling-for-agents.md) · **Decider:** Laurent Boucher

> **Note (2026-09-28).** The SIEM signature identifiers this record names as `ZAN-SEC-nnn` are
> emitted as `VECTI-SEC-nnn` since 0.10.0 — same numbers, same meanings. The text
> below is left as accepted; see the [SIEM catalogue](../../../../docs-site/integrations/siem.md#event-catalogue).

## Context

An agent in `delegated` mode receives a repository's SSH key or HTTPS token with each task, sealed
([`SealedEnvelope`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/crypto/SealedEnvelope.java):
X25519, HKDF, AES-256-GCM) for a public key the agent makes at every start. The purpose is stated
in that class: most deployments put a reverse proxy in front of the control plane, TLS ends there,
and sealing is what keeps the credential from whoever administers that proxy.

That purpose held only if the key the control plane sealed for was the agent's. It was taken from
the agent's `hello`, unsigned, over the very channel the sealing distrusts, and overwritten by every
later `hello` — an empty one included, after which the control plane fell back on sending the
credential in the clear over TLS. A party able to rewrite the channel could therefore choose the key
or remove it. The 2026-09-26 security audit recorded this as its last open finding.

The agent already holds one key the control plane did **not** learn over the agent protocol: the
Ed25519 result-signing key an administrator pins on the agent's row
([`ResultAttestation`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/crypto/ResultAttestation.java)).
Its private half is in the agent's configuration, its public half arrived through an
administrator's session.

## Decision

**Sealing takes a TLS-terminating proxy out of the trust boundary, given a pinned signing key.**
Concretely:

1. **The agent signs its sealing key with its pinned signing key**
   ([`SealingKeyAttestation`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/crypto/SealingKeyAttestation.java)).
   The signature is Ed25519 over
   `sha256("vectispire:agent-sealing-key:v1" ‖ 0x00 ‖ agentId ‖ 0x00 ‖ generation ‖ 0x00 ‖ sha256(key))`:
   - its own context string, distinct from the result's `vectispire:agent-result:v1`, so a signature
     made for one purpose never verifies for the other although one key makes both;
   - the agent's id (canonical UUID), so an announcement cannot be replayed onto another agent an
     operator configured with the same signing key;
   - the **generation** — when the pair was made, in epoch milliseconds — so the control plane keeps
     the newest and refuses an older announcement sent again;
   - the key's decoded SPKI bytes, which are what the envelope is sealed to.
2. **The announcement is a route of its own**, `POST /api/v1/agent/sealing-key`
   (`public_key`, `generation`, `signature`), called after the `hello` because the agent learns its
   id from the `hello`'s answer. It answers 204 when accepted, 412 when no signing key is pinned,
   403 when the signature does not verify, 409 when the generation is not newer than the key held.
   The 403 and the 409 are audited (`AGENT_SEALING_KEY_REFUSED`) and signal the SIEM event
   `ZAN-SEC-020`; an accepted change is audited (`AGENT_SEALING_KEY_ACCEPTED`).
3. **Sticky.** The `hello` no longer writes the sealing key; its unsigned `sealing_public_key` is
   read by nothing. The accepted key changes only through a correctly signed, newer announcement,
   written by one conditional statement, and the entity cannot write the column when a row is
   saved for another reason. A `hello` with no key, or with any unsigned key, leaves it in place.
4. **No clear delivery, ever.** A delegated credential leaves sealed for the verified key, or not
   at all. Whether the link is encrypted is no longer consulted: TLS that a proxy terminates
   protects nothing from that proxy, and from the control plane an announcement removed on the way
   looks exactly like an agent that never made one. **An agent that cannot be handed one does not
   claim a scan that needs one**: the repositories carrying a key or a token are left out of its
   selection, so the scan stays in the queue for an executor that can run it and **costs none of
   its attempts**; the agent still takes image scans and repositories without a credential. When
   such scans are all it has left, its poll answers 412 naming the step to take. The first version
   of this decision claimed the scan, withheld the credential and put it back — each poll spent an
   attempt, so a scan nothing had tried reached a capable executor with its takeovers used up,
   and its first lapsed lease failed it for good. Refunding the attempt was
   rejected: the same agent would have taken the same scan at every poll and kept it from a
   verified agent or the built-in worker. The attempt is refunded only in the race where a
   repository gains its key between the selection and the delivery, which the next selection
   closes.
5. **An agent with no pinned signing key is handed no delegated credential.** There is no trust on
   first use: the pair is remade at every start, so a key believed on first sight would have to be
   believed again, unsigned, after every restart — which is the finding again.
6. **The way back is an administrator's.** `DELETE /api/v1/admin/agents/{id}/sealing-key` forgets
   the key and its generation (`AGENT_SEALING_KEY_RESET`, SIEM `ZAN-SEC-014`); pinning, replacing or
   removing the signing key forgets it too, since the new key does not vouch for what the old one
   signed. The agent announces again at its next start, or at its next claim once a credential has
   been withheld after an acceptance.
7. **V40** adds `t_agent.sealing_key_generation` and forgets every stored sealing key: none had been
   verified.

## Compatibility

The agent contract stays `1`. Its rule is that the number changes when an older agent's behaviour
becomes *incorrect*; here an older agent is refused a credential explicitly and its every other
behaviour is unchanged. Bumping it would refuse older agents' `hello` outright, local ones included.

| Agent | Control plane | Outcome |
|---|---|---|
| this version, signing key pinned and configured | this version | credentials sealed for the verified key |
| this version, no signing key | this version | `local` works; delegated credentials withheld (412, logged by the agent) |
| older | this version | `hello` works, image scans and `local` work; delegated credentials withheld with a 412 the agent logs |
| this version | older | the `hello` still carries the unsigned key, which that control plane seals for; the signed route answers 404, read as "not supported" |

## Alternatives considered

- **Trust on first use.** Rejected for the reason in point 5: an ephemeral key has a first use at
  every start.
- **Keep the clear fallback over TLS for agents without a key.** It is exactly the downgrade the
  finding describes; the agent already refused such a credential, but only after the proxy had read
  it.
- **Sign the key inside the `hello`.** The agent does not know its id before the `hello` answers,
  and signing without it loses the binding to one agent.
- **A long-lived sealing key on the agent's disk, pinned like the signing key.** A second secret to
  provision, protect and rotate per agent, where signing the ephemeral one with the key already
  pinned costs nothing new.

## Consequences

- **An operator must pin a signing key before delegating credentials** — the lock icon on the
  agents screen, or `PUT /api/v1/admin/agents/{id}/signing-key` — and configure its private half as
  `VECTISPIRE_AGENT_SIGNING_KEY`. That key then also attests the agent's results; there is no way to
  have one without the other, and that is deliberate.
- An upgrade stops delegated scans of existing agents until both are done and the agent is
  upgraded. The claim's 412 and the screen's "credentials withheld" say so; nothing is sent in the
  clear meanwhile, and the delegated scans wait without spending their attempts — for as long as no
  executor able to run them polls, which only the agent's log and the screen's row reveal.
- A host whose clock goes back produces keys the control plane refuses as older; the fix is the
  clock or an administrator's reset.
- What this does **not** cover: whoever holds the agent's configuration — its signing key — can
  announce a key of their own; a compromised agent host is out of scope, as in 0003. A proxy can
  still drop the announcement or the claim: that denies service, it does not disclose the
  credential.

## Amends

[0003](0003-long-polling-for-agents.md) said a key is sealed "to the public key the agent announced
at enrolment". It is now sealed only to a key the agent's pinned signing key vouched for.

## Amendment — 2026-10-10: the envelope is bound to what it carries

**What this decision claimed and did not hold.** "Sealing takes a TLS-terminating proxy out of the
trust boundary" was secured in one direction only — the key the agent announces. In the other, an
HTTPS token was sealed alone while its host and user name travelled beside it in the clear (decision
[0022](0022-https-clone-tokens-are-bound-to-a-host.md) binds the clone to *that* host). The proxy
this decision excludes could rewrite the host and the clone URL, leave the envelope untouched, and
receive the token from the agent that opened it. A deployment key's envelope moved into the token's
field went the same way, as a password. An SSH key is not disclosed by a redirected clone; a token is.

**Decision.**

1. **Every envelope is sealed under a context**, authenticated by GCM with the sender's key:
   `deployment-key`, or `https-token` with the host and the user name, each length-prefixed. The agent
   opens a token only under the host and user name it arrived with, which are the ones the clone binds
   it to: a rewritten host leaves an envelope that does not open. The format becomes `sealed:v2:`
   (HKDF info `…:v2`), and a `sealed:v1:` envelope is refused by name — "a control plane older than
   this agent".
2. **The agent vouches for the format in its signed announcement.** The attestation's context becomes
   `vectispire:agent-sealing-key:v2`. An agent from before signs `…:v1`; the control plane refuses it
   like any announcement that does not verify (403, `AGENT_SEALING_KEY_REFUSED`), and checks the v1
   statement only to name the cause in the audit entry — *older than this control plane … Update the
   agent* — never to accept it.
3. **V86 forgets every sealing key accepted so far**, as V40 did: none vouched for the new format, and
   keeping one would seal for an agent that cannot open what it is sent. A current agent announces again
   at its next start.

**Compatibility.** The agent contract stays `1`, for the reason given above: an older agent is refused
a credential explicitly and every other behaviour is unchanged.

| Agent | Control plane | Outcome |
|---|---|---|
| 0.11.0 | 0.11.0 | credentials sealed under their context |
| older | 0.11.0 | `hello`, image scans and `local` work; its sealing key is refused by name, delegated credentials withheld (412) |
| 0.11.0 | older | its v2 announcement does not verify there; delegated credentials withheld; were one sealed in v1, the agent refuses it by name |

**Rejected.** *Bumping the agent contract* refuses older agents' `hello` outright, image scans and
`local` agents included, for a property only delegated credentials need. *Checking the host beside the
envelope* is the check that was missing; a binding inside the authentication cannot be forgotten by a
caller. *Signing every task with a control-plane key pinned on the agent* would authenticate the whole
assignment and is the stronger answer, but it is a second key to provision per installation; it stays
open for the day a task carries another secret.

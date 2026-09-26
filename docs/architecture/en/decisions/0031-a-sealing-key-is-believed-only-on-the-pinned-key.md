# 0031 — An agent's sealing key is believed only on the word of its pinned signing key

**Date:** 2026-09-26 · **Status:** accepted · **Amends:** [0003](0003-long-polling-for-agents.md) · **Decider:** Laurent Boucher

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
4. **No clear delivery, ever.** A delegated credential leaves sealed for the verified key, or the
   claim answers 412 naming the step to take and the scan goes back to the queue. Whether the link
   is encrypted is no longer consulted: TLS that a proxy terminates protects nothing from that
   proxy, and from the control plane an announcement removed on the way looks exactly like an
   agent that never made one.
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
  clear meanwhile.
- A host whose clock goes back produces keys the control plane refuses as older; the fix is the
  clock or an administrator's reset.
- What this does **not** cover: whoever holds the agent's configuration — its signing key — can
  announce a key of their own; a compromised agent host is out of scope, as in 0003. A proxy can
  still drop the announcement or the claim: that denies service, it does not disclose the
  credential.

## Amends

[0003](0003-long-polling-for-agents.md) said a key is sealed "to the public key the agent announced
at enrolment". It is now sealed only to a key the agent's pinned signing key vouched for.

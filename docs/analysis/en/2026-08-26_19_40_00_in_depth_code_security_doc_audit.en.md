# In-Depth Audit Report: Documentation, Source Code & Security

* **Project:** Vectispire — ASPM & Software Security Control Plane
* **Date:** 26 August 2026, 19:40
* **Commit audited:** `caa11096` (`develop`)
* **Scope:** the five axes of [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)

> **Thirteenth pass, the fourth today.** The three before it aimed at authorization, cryptography,
> the fingerprint contract and ADR-0007. This one aims at the last artefact thirteen passes have
> named without ever holding it against the code: **the STRIDE threat model**.
>
> A threat model is not documentation. It is a list of claims about what protects you, read by
> somebody who will sign something on the strength of it.

---

## 0. What was executed

| command | result |
|---|---|
| `./gradlew check` | **green** |
| `./gradlew integrationTestAll --rerun-tasks` | **green on all three engines** |
| `npx ng test --no-watch` | **23 files, 146 tests** |
| `npx playwright test` | 13 of 13 (earlier today, real browser) |

---

## 1. Summary

| Domain | Score | What sets it |
|---|:---:|---|
| **Documentation & Architecture** | **8.4 / 10** | **The STRIDE model describes a protection that does not exist**, in both languages |
| **Security & Cryptography** | **8.5 / 10** | The sandbox holds and is proven; the host-SSH fallback is on by default |
| **Code Quality** | **8.6 / 10** | ADR-0007 closed this morning; nothing new found |
| **Regulatory & Standards** | **9.3 / 10** | Unchanged |
| **Verification that runs** | **9.0 / 10** | Still no green nightly |

Documentation falls from 9.2 to 8.4. **The ground did not get worse**: twelve passes had scored an
artefact they had not held against the code.

---

## 2. 🔴 E1 — the threat model advertises a mitigation as off; it ships on

`STRIDE_THREAT_MODEL`, process **P2 — Scan Orchestrator**, in both languages:

| Threat | Advertised mitigation |
|---|---|
| *Orchestrator using host SSH key to clone unauthorized Git repositories* | **"Host SSH disabled by default (`host-ssh: false`)"** |

The real default, in [`application.yaml`](../../../vectispire-java/vectispire-core/src/main/resources/application.yaml):

```yaml
# A repository with no deployment key attached falls back to this machine's own ~/.ssh.
host-ssh: ${VECTISPIRE_HOST_SSH:…:true}
```

**`true`.** And `docker-compose.yml` does not merely enable it — it **supplies the keys**, to the
control plane *and* to the agent:

```yaml
- ${HOME}/.ssh:/home/vectispire/.ssh:ro
```

So the shipped deployment file assembles exactly the three conditions of the scenario the model
says it covers: the fallback is on, the operator's keys are mounted, and a repository without its
own key will use them.

### Why this is red and not a typo

A threat model is read by an external auditor, by a customer's security review, by whoever signs
off. They have no reason to go and check `application.yaml` — that is precisely the work the
document claims to have done for them. An advertised mitigation that is absent is worse than no
mitigation: it consumes the attention that would have gone into building one.

And **no test pins this either way**. It can flip without anything saying so.

### What is not mine to settle

Flipping the default to `false` would break installations that rely on the fallback: a repository
with no deployment key would stop cloning. That is an operator's trade.

**What is not a trade** is the document advertising a control that does not exist. Two acceptable
outcomes, one unacceptable — today's.

---

## 3. What was held against the code and holds

The same sweep checked the model's other claims, and they survive:

| STRIDE claim | check |
|---|---|
| "No scanner container mounts the Docker socket" | true — the `docker.sock` paths in the code are the control plane's **daemon discovery**, not mounts |
| "Total network isolation (`network: none`)" | `withNetworkMode(request.network() ? "bridge" : "none")`, and `ContainerHardeningTest` pins both: no network by default, **and** that asking for one loosens nothing else |
| "`cap_drop: ALL`, `no-new-privileges`, `read-only`" | captured off the real `HostConfig` by that same test |
| "Server-side enforced configuration" (ADR-0006) | the secrets scanner passes its own `--config` |
| "Zero JDBC drivers on the agent classpath" | a fact about the build graph, and `AgentIsolationTest` forbids the import |
| "`@PreAuthorize` and strict role verification" | true: `@RequiresAdministrator` and its siblings are meta-annotations built on it |

That is half an audit's work and it deserves writing down: **the model is mostly accurate**, which
is what makes the one false entry expensive.

---

## 4. Recommendations

| # | Action | How it was verified |
|---|---|---|
| 🔴 1 | Reconcile the STRIDE model with reality — **in both languages**. Either the default becomes `false` with its migration note, or the document states the real posture and the compensating control | **measured**: doc says `false`, `application.yaml` says `true`, `docker-compose.yml` mounts `${HOME}/.ssh` |
| 🟠 2 | A test pinning the `host-ssh` default, whichever it is | measured: no test mentions it |
| 🟡 3 | Hold the other STRIDE tables against the entities that did not exist when it was written (ticketing webhook, attack paths, SCIM) | not done: this pass checked the claims present, not the ones missing |

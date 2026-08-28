# CI policy gate

The gate answers one question from your pipeline: **should this build fail?**

## The short version

```bash
curl -sSL https://raw.githubusercontent.com/asmolabs/vectispire/main/ci/vectispire-gate.sh | sh
```

Or use the shipped integrations rather than writing the request by hand:

- [`ci/vectispire-gate.sh`](https://github.com/asmolabs/vectispire/blob/main/ci/vectispire-gate.sh) — a shell script for any runner;
- [`ci/github-action/action.yml`](https://github.com/asmolabs/vectispire/blob/main/ci/github-action/action.yml) — a GitHub composite action;
- [`ci/gitlab/vectispire-gate.gitlab-ci.yml`](https://github.com/asmolabs/vectispire/blob/main/ci/gitlab/vectispire-gate.gitlab-ci.yml) — a GitLab template.

All three need `VECTISPIRE_API_KEY` in the job environment, from an
[API key](../administration/api-keys.md) with the right scope.

## The verdict names its policy

The response says which policy it applied. That matters when a build fails and the author
wants to know what bar they were held to — "the global policy, version 4" is an answer;
"failed" is not.

## Policies are stored, not sent

**A `policy` object in the request can only *tighten* what applies, never loosen it.**

This was not always so. The rules used to arrive in the request body, which meant each
project decided its own bar, which meant the gate measured nothing comparable across the
estate. Now the applied policy is a **stored, versioned** one — global, or overridden per
target — written on **Administration → Gate policies**. A request can be stricter than it.
It cannot be laxer.

Where nothing is stored, the built-in default applies. The screen shows that default beside
what is stored, so that "not set" and "set to the same thing" do not look alike.

[Configuring policies →](../administration/gate-policies.md)

## What a policy can consider

| | |
|---|---|
| **Threshold** | the severity at which the build fails |
| **Fixable only** | ignore what has no published fix — you cannot ask a team to fix what upstream has not fixed |
| **Actively exploited** | treat KEV entries differently from the rest |
| **Triaged findings** | whether a triaged issue still counts |
| **License violations** | fail on a blocked license |
| **Model review** | whether an AI review verdict participates |

## Quality never fails a build

Semgrep quality findings cannot fail a gate, by construction rather than by configuration.
See [Code quality](../guide/quality.md) for why that boundary is load-bearing.

## Where to put the gate

After the scan and before the deploy. Two failure modes to avoid:

**Gating on a stale scan.** A verdict about last week's commit tells you nothing about this
one. Trigger the scan in the pipeline, then gate on it.

**Gating on a target that was never scanned.** An empty backlog passes every policy. See
[Reading the results](../getting-started/reading-results.md#two-states-with-an-empty-backlog).

## Annotating the pull request too

A gate is binary and arrives at the end. Export [SARIF](../guide/exports.md#sarif-210)
alongside it so the findings land on the diff, where they get fixed rather than triaged.

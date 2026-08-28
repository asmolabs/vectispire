# Gate policies

**Administration → Gate policies.** One global policy, overridden per target where needed.

## Stored and versioned

A policy is stored and carries a version, along with a **"why", kept with the version**.

The rationale field is not decoration. Six months on, "threshold: high" is a number nobody
can defend; "threshold: high, because criticals in transitive dependencies were failing
every build and teams had started bypassing the gate" is a decision somebody can revisit.

The rules used to arrive in the CI request body, which meant every project set its own bar
and nothing was comparable. Now a request can only **tighten** the stored policy, never
loosen it.

## The built-in default

Where nothing is stored, a built-in default applies. The screen shows it **beside** what
you have stored, so that "not set" and "set to the same thing" do not look alike — they
behave identically today and diverge the moment the default changes.

## What a policy sets

| | |
|---|---|
| **Fail the build at** | the severity threshold |
| **Fixable only** | ignore findings with no published fix |
| **Actively exploited** | how KEV entries are treated |
| **Triaged findings** | whether a triaged issue still counts |
| **License violations** | fail on a blocked license |
| **Model review** | whether an AI review verdict participates |

## Overrides

Per target. Use them for the cases the global policy genuinely cannot express — a Tier 1
service held to a stricter bar, a legacy target being brought up over a quarter.

Keep them few. An estate where every target has its own policy has no policy, and the
comparison the global bar existed to make becomes impossible again.

## Fixable only, in practice

Turning it on is usually right at first. Failing builds on findings with no published fix
asks teams to do something nobody can do, and a gate that cannot be satisfied is a gate
that gets bypassed.

Turn it off once the fixable backlog is under control — at which point unfixable criticals
are a real decision about whether to ship, rather than noise.

## Related

[CI policy gate](../integrations/ci-gate.md) · [Tracker tickets](../integrations/ticketing.md)
— which uses the same policy, deliberately.

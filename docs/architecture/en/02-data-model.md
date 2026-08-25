# 02 — Data model

## The distinction everything rests on: finding and issue

This is the one thing to understand before touching this schema.

- A **`Finding`** is what an analyzer said, during **one** scan. It is immutable and disposable. Re-running the scan produces a new one.
- An **`Issue`** is the same problem **tracked across scans**. It has a first detection, a times-seen counter, a state, a triage decision and its author.

```mermaid
erDiagram
    REPOSITORY ||--o{ SCAN : "is scanned by"
    CONTAINER  ||--o{ SCAN : "is scanned by"
    SCAN       ||--o{ FINDING : "produces"
    SCAN       ||--o{ ISSUE : "opens (first_seen)"
    ISSUE      }o--|| REPOSITORY : "concerns"
    ISSUE      }o--|| CONTAINER : "concerns"
    REPOSITORY ||--o| SSH_KEY : "clones with"
    REPOSITORY ||--o| GATE_POLICY : "evaluated by"
    CONTAINER  ||--o| GATE_POLICY : "evaluated by"
    SCAN       }o--o| AGENT : "claimed by"
    SCAN       ||--o{ AI_REVIEW_RESULT : "carries"
```

## The fingerprint

An issue's identity across scans, computed by `buildFingerprint`:

```
sha256( target, type, identifier, purl-or-package-name, file-path )
```

## An issue's life cycle

```mermaid
stateDiagram-v2
    [*] --> open : first detection
    open --> open : seen again (times_seen++)
    open --> resolved : absent from a scan that looked for this type
    resolved --> open : reappears
    open --> under_review : triage
    under_review --> not_affected : with a VEX justification
    under_review --> affected
    not_affected --> under_review : triage expiry
```

## The migrations

Managed by Flyway under `vectispire-java/vectispire-core/src/main/resources/db/migration/{vendor}/` (`postgresql`, `mysql`, `sqlite`), with dialect-specific native SQL scripts ensuring complete fidelity on each database engine.

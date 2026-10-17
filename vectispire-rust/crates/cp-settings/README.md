# vectispire-cp-settings

The control plane's settings module in Rust — `core.settings` and the catalog `common.domain.settings` (plan,
Phase 1 task 1.6). In progress, not shipped: the Java control plane is the product.

## The catalog

`src/catalog.rs` is **generated** from `reference/settings/catalog.json`, which the Java side writes
(`SettingsReferenceSetTest`), by `scripts/generate-catalog.py`. Every key, type, section, label, help text,
default and sensitivity is Java's; `tests/reference_set.rs` fails while the two disagree, including on the rules
that decide who may write a setting and whether the SOC hears of a change:

| Rule | Where |
|---|---|
| `directs_credential` — whoever may point a credential somewhere must be allowed to hold it | generated from the catalog, as Java's `switch` |
| `administrator_only` | `src/rules.rs`, as Java writes it |
| `governor_only` — the access, triage and checklist sections, and the evidence window | generated, as Java's `switch` |
| `governs_security` — **no wildcard arm**: a setting added does not compile until someone answered | generated |

After a change to the Java catalog: regenerate the reference set, run the script, read the diff.

## What a value must look like

`Setting::validate` answers in Java's words, held to `reference/settings/validation.json` — 54 settings × some
sixty inputs: every type's edges, `Integer.parseInt`'s (a sign, any script's decimal digits — the table of zeros
is Java's, `reference/settings/digit-zeros.txt` — `i32`), the text ceiling in UTF-16 units, and the tracker URL's
user-info refusal (`RepositoryUrl.carriesCredential`, or `java.net.URI`'s raw user info, which catches
`ssh://git@host` and a scheme-less `//user@host`).

## The store

`Settings` is `SettingsService`: reads with the catalog's default for an absent row and the stored value even
when empty; `set` and `set_internal` update then insert, in the caller's transaction; and the two writes that
arbitrate between instances, each tested on both engines with real concurrency:

- `store_internal_if_absent` — an insert on its own connection, the primary key the arbiter: of eight
  instances storing one key at once, exactly one is told it did, and all read back the winner.
- `replace_internal` — an update conditioned on the value read, in the caller's transaction: the second of two
  waits on the first's row lock and is told the value moved.

MySQL answers an update with the rows it *found*, as Connector/J has Hibernate see it, because sqlx asks for
found rows (`CLIENT_FOUND_ROWS`): writing a value a row already holds is still a write onto that row.

```sh
cargo test -p vectispire-cp-settings    # the reference set, and the store on both engines (Docker)
```

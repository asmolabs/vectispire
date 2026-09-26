# Common migrations

A migration that differs between engines only by its column types is written **once**, here, from
V40 on, with the type placeholders `MigrationDialect` spells per engine: `${ts}`, `${id}`, `${bool}`,
`${true}`, `${false}`, `${text}`, `${double}`. A new table's key is `id ${id},` — the placeholder
carries `primary key` itself, because SQLite only accepts `autoincrement` on the exact phrase
`integer primary key`.

A migration whose **structure** diverges is written three times, in `../mysql`, `../postgresql`
and `../sqlite`: a foreign key (MySQL discards an inline `references`, SQLite cannot add one
afterwards), a column change, date arithmetic, a data repair.

A version lives in exactly one of the two places. `MigrationLayoutTest` fails the build otherwise,
and refuses an engine-specific token in a file here. V1 to V39 predate the rule and are never moved
or edited: Flyway checks the checksum of every applied migration, and a changed one stops every
existing installation at startup.

See [decision 0027](../../../../../../../docs/architecture/en/decisions/0027-common-migrations-with-type-placeholders.md).

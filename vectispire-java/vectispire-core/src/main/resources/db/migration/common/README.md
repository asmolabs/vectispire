# Common migrations

A migration that differs between engines only by its column types is written **once**, here, from
V40 on, with the type placeholders `MigrationDialect` spells per engine: `${ts}`, `${id}`, `${bool}`,
`${true}`, `${false}`, `${text}`, `${double}`, `${bytes}`. A new table's key is `id ${id},` — the placeholder
carries `primary key` itself, a shape the SQLite fixture once needed and the migrations written
since keep (decision 0034 removed the fixture).

A migration whose **structure** diverges is written twice, in `../mysql` and `../postgresql`: a
foreign key (MySQL discards an inline `references`; write a named constraint), a column change,
date arithmetic, a data repair.

A version lives in exactly one of the two places. `MigrationLayoutTest` fails the build otherwise,
and refuses an engine-specific token in a file here. V1 to V39 predate the rule and are never moved
or edited: Flyway checks the checksum of every applied migration, and a changed one stops every
existing installation at startup.

See [decision 0027](../../../../../../../../docs/architecture/en/decisions/0027-common-migrations-with-type-placeholders.md).

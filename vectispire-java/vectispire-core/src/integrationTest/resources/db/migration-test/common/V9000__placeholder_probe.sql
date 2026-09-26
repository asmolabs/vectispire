-- A common migration that uses every type placeholder, applied by the campaign only
-- (`MigrationPlaceholdersIntegrationTest`), so that what `MigrationDialect` promises is measured
-- on each engine rather than read (decision 0027).
--
-- It lives outside `src/main`, on a location only that test adds: the production schema, and the
-- table list `MigrationsTest` pins, never see it. The version is far above any real one so that it
-- runs after the whole production set, on the schema a deployment would have.

create table t_placeholder_probe (
    id ${id},
    label varchar(40) not null,
    observed_at ${ts} not null,
    unset_flag ${bool} not null default ${false},
    set_flag ${bool} not null default ${true},
    body ${text},
    score ${double}
);

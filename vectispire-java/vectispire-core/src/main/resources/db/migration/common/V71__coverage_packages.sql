-- A coverage import's counts per package — decision 0032, amendment of 2026-10-03 (the scope of a
-- `coverage_threshold` rule).
--
-- Written once, in common: a column added and a new table with no foreign key. A package names its
-- import by id; the `plugins` module's listener removes a repository's packages before its imports
-- (`TargetDeleted`), as it does the test suites.

-- Whether the import's packages were kept: `kept`, or why not — `too_many` (more than 10,000),
-- `path_refused` (a path past 1,000 characters or carrying a control character), `inconsistent` (they
-- did not add up to the report's totals). Null for every import accepted before this migration: those
-- kept no package, and a scoped rule reads them as "re-import needed", never as an empty report.
alter table t_coverage_import add column packages_state varchar(20);

-- One package of a kept import: a JaCoCo or Cobertura package with its dots read as slashes, or the
-- directory holding an lcov file — `org/example/service`, the top level as ''. Branch counts are null
-- when the report counted no branch, as on the import. Rows never outlive their import, and an import
-- is kept as long as its repository: the same lifetime as `t_test_suite_result`.
create table t_coverage_package (
    id ${id},
    import_id bigint not null,
    path varchar(1000) not null,
    lines_covered bigint not null,
    lines_total bigint not null,
    branches_covered bigint,
    branches_total bigint
);

create index idx_coverage_package_import on t_coverage_package (import_id);

-- Coverage and test reports from declared internal sources — decision 0032 §7, amending 0017 §7.
--
-- Written once, in common: new tables with no foreign key, and a column added with a default. The
-- rows naming a repository are removed by the `plugins` module's listener when it goes
-- (`TargetDeleted`), as the SARIF imports are: a foreign key would have to be written three times.

-- The report kinds a declared source may deliver — `sarif`, `coverage`, `test_report`, comma-separated.
-- Every source declared before this is a SARIF source, and stays one: the default says so for the rows
-- already stored, and nothing else is granted by the upgrade.
alter table t_sarif_source add column kinds varchar(100) not null default 'sarif';

-- One accepted coverage report: the source and key that sent it, what it counted, and what the
-- pipeline says it measured — `commit_sha` and `branch_name` are the pipeline's word, verified
-- against nothing. Branch counts are null when the report counted no branch: that is not 0 of 0.
create table t_coverage_import (
    id ${id},
    source_id bigint not null,
    source_slug varchar(40) not null,
    repo_id bigint not null,
    format varchar(20) not null,
    tool_version varchar(100),
    lines_covered bigint not null,
    lines_total bigint not null,
    branches_covered bigint,
    branches_total bigint,
    commit_sha varchar(64),
    branch_name varchar(255),
    document_sha256 varchar(64) not null,
    imported_at ${ts} not null,
    imported_by varchar(255) not null,
    api_key_id char(36) not null
);

create index idx_coverage_import_repo on t_coverage_import (repo_id, imported_at);

-- One accepted test report — a JUnit document or a zip of them — and its totals.
create table t_test_report_import (
    id ${id},
    source_id bigint not null,
    source_slug varchar(40) not null,
    repo_id bigint not null,
    format varchar(20) not null,
    documents_count int not null,
    suites_count int not null,
    tests_count int not null,
    failures_count int not null,
    errors_count int not null,
    skipped_count int not null,
    commit_sha varchar(64),
    branch_name varchar(255),
    document_sha256 varchar(64) not null,
    imported_at ${ts} not null,
    imported_by varchar(255) not null,
    api_key_id char(36) not null
);

create index idx_test_report_import_repo on t_test_report_import (repo_id, imported_at);

-- Each suite of an accepted test report, counted from its test cases. The cases themselves are not
-- stored in this version.
create table t_test_suite_result (
    id ${id},
    import_id bigint not null,
    name varchar(500) not null,
    tests_count int not null,
    failures_count int not null,
    errors_count int not null,
    skipped_count int not null
);

create index idx_test_suite_result_import on t_test_suite_result (import_id);

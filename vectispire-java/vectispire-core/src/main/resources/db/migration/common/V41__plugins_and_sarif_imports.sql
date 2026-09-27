-- Plugins (third-party analysers run as containers) and SARIF imports from declared internal
-- sources — decision 0017, as amended on 2026-09-27.
--
-- Written once, in common: new tables with no foreign key, nullable columns added to existing
-- tables, and a boolean with a default. The rows that name a project or a repository are removed
-- by the `plugins` module's listeners when either goes (`ProjectDeleted`, `TargetDeleted`), not by a
-- cascade: a foreign key would have to be written three times, and the listeners are what the
-- modules already rely on for rows in other tables.

-- A registered plugin. `id` is the slug that enters every one of its issues' fingerprints, so it is
-- the key and never changes; `manifest_digest` names the manifest the next scan runs.
create table t_plugin (
    id varchar(40) not null primary key,
    name varchar(100) not null,
    manifest_digest varchar(64) not null,
    enabled ${bool} not null,
    created_at ${ts} not null,
    created_by varchar(255) not null,
    updated_at ${ts} not null,
    updated_by varchar(255) not null
);

-- Every manifest a plugin ever had, by digest, and never rewritten: a task queued before an update
-- still names the manifest it was built with, and an agent fetches exactly that one.
create table t_plugin_manifest (
    digest varchar(64) not null primary key,
    plugin_id varchar(40) not null,
    manifest ${text} not null,
    created_at ${ts} not null
);

-- Which projects a plugin analyses. Nothing is global: a plugin reads every file it is given, and
-- a repository filed in no project runs none.
create table t_plugin_activation (
    id ${id},
    plugin_id varchar(40) not null,
    project_id bigint not null,
    activated_at ${ts} not null,
    activated_by varchar(255) not null,
    constraint uq_plugin_activation unique (plugin_id, project_id)
);

-- A declared internal source of SARIF: one integration key, one scope (a project or a repository,
-- never the estate), the tools it may deliver. One key is one source, so the key names the source.
create table t_sarif_source (
    id ${id},
    slug varchar(40) not null,
    name varchar(100) not null,
    api_key_id char(36) not null,
    project_id bigint,
    repository_id bigint,
    tools varchar(1000) not null,
    enabled ${bool} not null,
    created_at ${ts} not null,
    created_by varchar(255) not null,
    constraint uq_sarif_source_slug unique (slug),
    constraint uq_sarif_source_key unique (api_key_id)
);

-- One accepted import: what was declared, by which source and key, and what it did to the backlog.
-- The dated evidence an imported issue has, where a scanned one has its scan.
create table t_sarif_import (
    id ${id},
    source_id bigint not null,
    source_slug varchar(40) not null,
    repo_id bigint not null,
    tools varchar(1000) not null,
    document_sha256 varchar(64) not null,
    results_count int not null,
    created_count int not null,
    resolved_count int not null,
    reopened_count int not null,
    imported_at ${ts} not null,
    imported_by varchar(255) not null,
    api_key_id char(36) not null
);

create index idx_sarif_import_repo on t_sarif_import (repo_id, imported_at);

-- The provenance of a plugin or imported issue, and the scope a clean run resolves: `tool` is the
-- fingerprint's tool key (plugin:<id>, import:<source>/<tool>); the name and version are the SARIF
-- driver's, for display; `import_source` names the declared source for an imported one.
alter table t_issue add column tool varchar(200);
alter table t_issue add column tool_name varchar(100);
alter table t_issue add column tool_version varchar(100);
alter table t_issue add column import_source varchar(40);

-- What became of each plugin in a scan — produced, not applicable, absent — as a JSON array. Not
-- applicable is a report, not a silence, and it appears nowhere else: an absent plugin is also among
-- the scan's failures, a not-applicable one is not.
alter table t_scan add column plugin_steps ${text};

alter table t_finding add column tool varchar(200);
alter table t_finding add column tool_name varchar(100);
alter table t_finding add column tool_version varchar(100);

-- Plugin and imported findings weigh on a gate only when its policy says so; off for every
-- policy already stored, as for a new one.
alter table t_gate_policy add column include_plugins ${bool} not null default ${false};

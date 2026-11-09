-- The report plugins' registry — decision 0035 §4, lot R2: the plugins, every manifest each ever had by
-- digest with its approval and its withdrawal, and the projects each is switched on for.
--
-- Written once, in common: new tables, no foreign key. Apart from the scanner plugins' `t_plugin` on
-- purpose (0035 §4): a report plugin has a media type, an export major, an approval and a withdrawal, and
-- none of a scanner's languages or exit codes — one table would make every rule of each conditional on
-- the other's kind. The activations naming a project are removed by the `reportplugins` module's listener
-- when the project goes (`ProjectDeleted`), not by a cascade.

-- A registered report plugin. `id` is never renamed nor reused: documents in the world name it.
-- `approved_digest` is the manifest a run uses — null until one is approved, and again after it is
-- withdrawn; `pending_digest` the one awaiting a second person's approval, if any. `revision` is the
-- optimistic lock every write compares, so that an approval racing an update approves what it read.
create table t_report_plugin (
    id varchar(40) not null primary key,
    name varchar(100) not null,
    approved_digest varchar(64),
    pending_digest varchar(64),
    enabled ${bool} not null,
    revision bigint not null,
    created_at ${ts} not null,
    created_by varchar(255) not null,
    updated_at ${ts} not null,
    updated_by varchar(255) not null
);

-- Every manifest a report plugin ever had, by digest. The manifest itself is never rewritten; its
-- status moves pending_approval → approved, pending_approval → superseded, or any → withdrawn, never back.
-- `registered_by_id` is the account four-eyes compares the approver with; `approval_four_eyes` says
-- whether the rule applied when it was approved (false: four-eyes was off). The withdrawal's
-- justification is 20 to 500 characters, and stays: a withdrawn digest's documents are served with it.
create table t_report_plugin_manifest (
    digest varchar(64) not null primary key,
    plugin_id varchar(40) not null,
    manifest ${text} not null,
    status varchar(20) not null,
    registered_at ${ts} not null,
    registered_by varchar(255) not null,
    registered_by_id bigint not null,
    approved_at ${ts},
    approved_by varchar(255),
    approved_by_id bigint,
    approval_four_eyes ${bool},
    withdrawn_at ${ts},
    withdrawn_by varchar(255),
    withdrawal_justification varchar(500)
);

create index idx_report_plugin_manifest_plugin on t_report_plugin_manifest (plugin_id, registered_at);

-- Which projects a report plugin may be asked to render. Nothing is global: a report reads a project's
-- whole triaged state.
create table t_report_plugin_activation (
    id ${id},
    plugin_id varchar(40) not null,
    project_id bigint not null,
    activated_at ${ts} not null,
    activated_by varchar(255) not null,
    constraint uq_report_plugin_activation unique (plugin_id, project_id)
);

create index idx_report_plugin_activation_project on t_report_plugin_activation (project_id);

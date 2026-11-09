-- The report plugins' runs — decision 0035 §2, lot R3: a report requested for a project, queued here, claimed
-- by the control plane's executor, and what came of it; and the export a produced run was given, kept apart.
--
-- Written once, in common: new tables, no foreign key. A project's runs and exports are removed by the
-- `reportplugins` module's listener when the project goes (`ProjectDeleted`), the exports' bytes by the
-- maintenance tick past the evidence window; a run's row and its digests stay as long as the audit log.

-- One report run. `state` is pending, running, produced, failed or refused; `reason` the closed word of a
-- failed or refused one, `detail` its sentence. `active_key` is "<plugin>@<project>" while the run is pending
-- or running and null once it ended: unique, so a second request for the same plugin and project waits for
-- the first instead of rendering the same export twice — both engines admit any number of nulls in a unique
-- index, which a partial index would have said only on PostgreSQL. `claimed_by` and `lease_expires_at` are the
-- queue's, as for a scan: the take is a conditional update, and a lease that lapses fails the run
-- (`executor_lost`). The manifest is the one approved when the run was claimed — the instant the document
-- describes — so an approval between the request and the claim is what runs, never an unapproved digest.
create table t_report_run (
    id ${id},
    project_id bigint not null,
    project_name varchar(255),
    plugin_id varchar(40) not null,
    state varchar(20) not null,
    reason varchar(40),
    detail varchar(2000),
    active_key varchar(80),
    requested_at ${ts} not null,
    requested_by varchar(255) not null,
    requested_by_id bigint not null,
    requester_locale varchar(35),
    claimed_by varchar(100),
    lease_expires_at ${ts},
    started_at ${ts},
    exported_at ${ts},
    finished_at ${ts},
    manifest_digest varchar(64),
    image_digest varchar(71),
    signer_identity varchar(500),
    signer_issuer varchar(500),
    signer_key_sha256 varchar(64),
    export_schema_version varchar(10),
    export_sha256 varchar(64),
    export_size bigint,
    exit_code integer,
    output_size bigint,
    output_sha256 varchar(64),
    product_version varchar(100),
    constraint uq_report_run_active unique (active_key)
);

create index idx_report_run_state on t_report_run (state, requested_at);
create index idx_report_run_project on t_report_run (project_id, requested_at);

-- The export a produced run handed its plugin, byte for byte: what the run's provenance attests to includes
-- its input, and an input nobody can produce later is a claim nobody can check (0035 §3). Apart from the run,
-- read by no listing; purged with the evidence window, the run's row and its digest staying.
create table t_report_export (
    run_id bigint not null primary key,
    content ${bytes} not null,
    sha256 varchar(64) not null,
    size_bytes bigint not null,
    created_at ${ts} not null
);

create index idx_report_export_created on t_report_export (created_at);

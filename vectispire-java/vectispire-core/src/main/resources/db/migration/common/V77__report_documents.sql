-- The report plugins' documents — decision 0035 §3, lot R4: the output of a produced run, checked on its bytes
-- against its declared type, signed by the platform's key and kept as the package a recipient downloads.
--
-- Written once, in common: a new table and nullable columns added to one, no foreign key. A project's documents
-- are removed by the `reportplugins` module's listener when the project goes (`ProjectDeleted`), the bytes by the
-- maintenance tick past the evidence window; the run's row and its digests stay as long as the audit log.

-- What the run's provenance names beside the digests R3 already records: the output's declared type, which the
-- check held the bytes to; the platform key the package was signed with, by its id (the SHA-256 of the public
-- key); and the package's own SHA-256 — the zip a recipient holds, as the download's audit entry names it.
alter table t_report_run add column output_media_type varchar(120);
alter table t_report_run add column signing_key_id varchar(64);
alter table t_report_run add column package_sha256 varchar(64);

-- The package of a produced run, byte for byte: the plugin's file, its detached signature and the signed
-- provenance, as one zip. Apart from the run, like the export beside it: no listing reads up to the 50 MiB of an
-- output a row; purged with the evidence window, the run's row and its digests staying.
create table t_report_document (
    run_id bigint not null primary key,
    content ${bytes} not null,
    sha256 varchar(64) not null,
    size_bytes bigint not null,
    created_at ${ts} not null
);

create index idx_report_document_created on t_report_document (created_at);

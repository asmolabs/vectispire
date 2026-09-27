-- EPSS becomes FIRST's daily file, synchronised and stored like the KEV catalogue, instead of a
-- question each scan asked api.first.org about the CVE it had just found — which told a third party
-- which vulnerabilities each repository carried, and did not work without outbound access.
--
-- `t_epss_score` holds every scored CVE, some 380,000 rows, under a **generation**: a
-- synchronisation writes a new one beside the one in use, in short batches, and switches to it in
-- one short transaction once the whole file is written and checked. Readers only ever see the
-- generation the sync row names, so a file refused half-way — or a sync that dies — leaves the
-- scores in use untouched, and no transaction holds 380,000 rows' worth of locks. The key leads
-- with the generation because every read and every delete names one.
--
-- The sync row gains the feed's own state, beside the KEV catalogue's: its status and last error,
-- the model version and score date the file declared (the age of the data, which the date of the
-- sync does not give), the rows it carried, the generation in use, when it was last tried, and a
-- lease with its claim — which generation a synchronisation is writing and until when — so that
-- two instances, or the schedule and a lead's button, never write at once. 500 is `epss_error`'s
-- bound, as on the other error columns.
--
-- `epss_score` and `epss_percentile` leave `t_threat_intel_feed`: nothing has written them since
-- V43 emptied the table, and kept they would read as a second place EPSS is stored.
--
-- Written once, in common: a new table without a foreign key, nullable or defaulted columns added,
-- and columns dropped with the statement every engine reads alike.

create table t_epss_score (
    generation bigint not null,
    cve_id varchar(32) not null,
    score ${double} not null,
    percentile ${double} not null,
    primary key (generation, cve_id)
);

alter table t_threat_intel_sync add column epss_status varchar(32) not null default 'NEVER_SYNCED';
alter table t_threat_intel_sync add column epss_synced_at ${ts};
alter table t_threat_intel_sync add column epss_model_version varchar(32);
alter table t_threat_intel_sync add column epss_score_date ${ts};
alter table t_threat_intel_sync add column epss_count bigint not null default 0;
alter table t_threat_intel_sync add column epss_generation bigint;
alter table t_threat_intel_sync add column epss_attempt_at ${ts};
alter table t_threat_intel_sync add column epss_lease_until ${ts};
alter table t_threat_intel_sync add column epss_claim bigint;
alter table t_threat_intel_sync add column epss_error varchar(500);

alter table t_threat_intel_feed drop column epss_score;
alter table t_threat_intel_feed drop column epss_percentile;

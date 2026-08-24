create table t_threat_intel_feed (
    cve_id varchar(64) not null primary key,
    is_kev boolean not null default 0,
    epss_score double,
    epss_percentile double,
    date_added timestamp,
    updated_at timestamp not null
);

create table t_threat_intel_sync (
    id integer not null primary key,
    last_synced_at timestamp,
    cve_count integer not null default 0,
    kev_count integer not null default 0,
    status varchar(32) not null default 'SYNCED'
);

create table t_threat_intel_feed (
    cve_id varchar(64) not null primary key,
    is_kev boolean not null default false,
    epss_score double precision,
    epss_percentile double precision,
    date_added timestamp with time zone,
    updated_at timestamp with time zone not null
);

create table t_threat_intel_sync (
    id bigint not null primary key,
    last_synced_at timestamp with time zone,
    cve_count bigint not null default 0,
    kev_count bigint not null default 0,
    status varchar(32) not null default 'SYNCED'
);

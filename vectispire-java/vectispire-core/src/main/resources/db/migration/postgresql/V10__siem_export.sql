create table t_siem_config (
    id bigint primary key,
    enabled boolean not null default false,
    protocol varchar(16) not null default 'WEBHOOK',
    endpoint varchar(1024),
    auth_header varchar(512),
    min_severity varchar(32) not null default 'HIGH',
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp
);

create table t_license_policy (
    id bigint not null primary key,
    disallowed_categories varchar(255) not null default 'STRONG_COPYLEFT,FORBIDDEN',
    allowed_licenses text,
    disallowed_licenses text,
    updated_at timestamp not null default current_timestamp
);

insert into t_license_policy (id, disallowed_categories, allowed_licenses, disallowed_licenses, updated_at)
values (1, 'STRONG_COPYLEFT,FORBIDDEN', '', '', now());

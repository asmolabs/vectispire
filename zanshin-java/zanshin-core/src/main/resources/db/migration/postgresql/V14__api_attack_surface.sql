create table t_api_endpoint (
    id bigint generated always as identity primary key,
    scan_id bigint not null references t_scan(id) on delete cascade,
    repository_id bigint references t_repository(id) on delete cascade,
    http_method varchar(20) not null,
    path varchar(1000) not null,
    auth_required boolean not null default false,
    auth_type varchar(50),
    visibility varchar(20) not null default 'UNKNOWN',
    file_path varchar(1000),
    line_number int,
    framework varchar(50),
    operation_id varchar(255),
    summary varchar(500),
    tags varchar(255),
    created_at timestamp with time zone not null
);

create table t_api_contract (
    id bigint generated always as identity primary key,
    repository_id bigint not null references t_repository(id) on delete cascade,
    scan_id bigint references t_scan(id) on delete cascade,
    contract_path varchar(1000) not null,
    format varchar(50),
    title varchar(255),
    version varchar(50),
    endpoints_count int not null default 0,
    created_at timestamp with time zone not null
);

create index idx_api_endpoint_repo on t_api_endpoint(repository_id, scan_id);
create index idx_api_endpoint_path on t_api_endpoint(path, http_method);
create index idx_api_contract_repo on t_api_contract(repository_id);

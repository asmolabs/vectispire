create table t_component (
    id bigint auto_increment primary key,
    scan_id bigint not null references t_scan(id) on delete cascade,
    name varchar(255) not null,
    version varchar(255),
    purl varchar(500),
    type varchar(50),
    is_direct bit(1)
);

create index idx_component_search on t_component(name, version, scan_id);

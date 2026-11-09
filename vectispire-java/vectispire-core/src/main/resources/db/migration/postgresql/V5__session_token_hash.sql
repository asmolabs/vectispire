drop table t_session;

create table t_session (
    token_hash varchar(64) not null primary key,
    user_id bigint not null references t_user(id) on delete cascade,
    created_at timestamp with time zone not null,
    last_seen_at timestamp with time zone not null,
    expires_at timestamp with time zone not null,
    user_agent varchar(255),
    ip_address varchar(64)
);

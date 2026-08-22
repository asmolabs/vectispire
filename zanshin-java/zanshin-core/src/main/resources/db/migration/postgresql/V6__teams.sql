create table t_team (
    id bigint generated always as identity primary key,
    name varchar(100) not null unique,
    description varchar(255),
    created_at timestamp with time zone not null
);

create table t_team_member (
    team_id bigint not null references t_team(id) on delete cascade,
    user_id bigint not null references t_user(id) on delete cascade,
    primary key (team_id, user_id)
);

create table t_team_target (
    team_id bigint not null references t_team(id) on delete cascade,
    target_kind varchar(20) not null,
    target_id bigint not null,
    primary key (team_id, target_kind, target_id)
);

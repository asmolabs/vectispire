create table t_team (
    id bigint auto_increment primary key,
    name varchar(100) not null unique,
    description varchar(255),
    created_at datetime(6) not null
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

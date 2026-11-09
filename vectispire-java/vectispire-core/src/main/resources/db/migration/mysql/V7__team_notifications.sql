create table t_team_webhook (
    team_id bigint not null primary key references t_team(id) on delete cascade,
    url varchar(500) not null
);

alter table t_outbox_message add column team_id bigint;

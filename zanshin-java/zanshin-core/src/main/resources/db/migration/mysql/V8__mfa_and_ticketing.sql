alter table t_user add column mfa_enabled boolean not null default false;
alter table t_user add column totp_secret text;
alter table t_user add column mfa_backup_codes text;

create table t_issue_ticket (
    id bigint not null auto_increment primary key,
    issue_id bigint not null,
    provider varchar(32) not null,
    ticket_key varchar(128) not null,
    ticket_url varchar(512) not null,
    status varchar(64) not null,
    created_at datetime(6) not null,
    updated_at datetime(6) not null,
    constraint fk_issue_ticket_issue foreign key (issue_id) references t_issue(id) on delete cascade
);

create index idx_issue_ticket_issue_id on t_issue_ticket(issue_id);

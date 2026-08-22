create table t_issue_triage_event (
    id bigint generated always as identity primary key,
    issue_id bigint not null references t_issue(id) on delete cascade,
    from_status varchar(30) not null,
    to_status varchar(30) not null,
    justification varchar(64),
    comment text,
    actor varchar(255),
    origin varchar(20) not null,
    occurred_at timestamp with time zone not null,
    expires_at timestamp with time zone,
    scan_id bigint references t_scan(id) on delete set null
);

create index idx_triage_event_issue on t_issue_triage_event(issue_id, occurred_at, id);

-- The foreign keys the schema has always claimed, made real on MySQL.
--
-- **Twenty-four columns are declared `references t_x(id) on delete …` inline, inside the column
-- definition, and MySQL parses that form and discards it.** No constraint, no index, no cascade —
-- only the table-level `constraint … foreign key (…) references …` creates one. The proof is a
-- table in this schema: `t_issue_ticket` (V8) used the table-level form and is the single
-- referential constraint MySQL has ever enforced here. The other twenty-four read like keys and
-- are ordinary integers.
--
-- **What was actually at risk, and what was not.** Deletion is not the exposure: every path that
-- removes a target, a team or a user already deletes its children explicitly, in code, in the
-- right order — `TargetDeletionService` for scans and their findings, `TeamsController.remove`
-- for memberships, assignments and the channel. That code exists because SQLite ignores cascades
-- too unless `PRAGMA foreign_keys = ON` is issued, and somebody measured a webhook row surviving
-- its team. So the product does not depend on the database to cascade.
--
-- What was at risk is everything that code does not cover: a crash between two of those deletes,
-- a future path that forgets a table, a repair run by hand at the prompt, a restore of one table.
-- **The application enforcing an invariant is the application remembering to; the constraint is
-- the database refusing to forget.** The gap between those two is where orphans come from, and an
-- orphan here is a finding, a session or a team membership pointing at something that is gone.
--
-- **This migration deletes rows, and on a healthy deployment it deletes none.** Every statement
-- below is a no-op unless the orphans it names already exist — in which case they are unreachable
-- from every query path in the product, because every one of those paths joins through the parent
-- that is missing. They are removed here rather than reported because a constraint cannot be
-- added over them, and leaving the schema honest matters more than preserving rows nothing can
-- read. The order is top-down: orphaned scans go before the findings that hang off them, so the
-- second wave sees the wreckage the first one made.
--
-- PostgreSQL needs none of this — it builds the constraint from the inline form, verified against
-- the engine — and SQLite cannot be altered into one; its half is the pragma, which is a
-- connection setting and not a migration.

-- ---------------------------------------------------------------- orphans, first wave: targets
delete from t_scan where repo_id is not null and repo_id not in (select id from t_repository);
delete from t_scan where container_id is not null and container_id not in (select id from t_container);
delete from t_issue where repo_id is not null and repo_id not in (select id from t_repository);
delete from t_issue where container_id is not null and container_id not in (select id from t_container);

-- ------------------------------------------- orphans, second wave: what hung off what just went
delete from t_finding where scan_id not in (select id from t_scan);
delete from t_component where scan_id not in (select id from t_scan);
delete from t_ai_review_result where scan_id not in (select id from t_scan);
delete from t_api_endpoint where scan_id not in (select id from t_scan);
delete from t_api_endpoint where repository_id is not null and repository_id not in (select id from t_repository);
delete from t_api_contract where repository_id not in (select id from t_repository);
delete from t_api_contract where scan_id is not null and scan_id not in (select id from t_scan);
delete from t_issue_triage_event where issue_id not in (select id from t_issue);

-- `set null` columns lose their pointer rather than their row: that is what the declaration asks
-- for, and a finding whose issue was merged away is still a finding.
update t_issue_triage_event set scan_id = null
 where scan_id is not null and scan_id not in (select id from t_scan);
update t_finding set issue_id = null
 where issue_id is not null and issue_id not in (select id from t_issue);
update t_issue set first_seen_scan_id = null
 where first_seen_scan_id is not null and first_seen_scan_id not in (select id from t_scan);
update t_issue set last_seen_scan_id = null
 where last_seen_scan_id is not null and last_seen_scan_id not in (select id from t_scan);

-- ------------------------------------------------------ orphans, third wave: people and secrets
delete from t_session where user_id not in (select id from t_user);
delete from t_user_target where user_id not in (select id from t_user);
delete from t_team_member where team_id not in (select id from t_team);
delete from t_team_member where user_id not in (select id from t_user);
delete from t_team_target where team_id not in (select id from t_team);
delete from t_team_webhook where team_id not in (select id from t_team);
update t_agent set api_key_id = null
 where api_key_id is not null and api_key_id not in (select id from t_api_key);
update t_repository set ssh_key_id = null
 where ssh_key_id is not null and ssh_key_id not in (select id from t_ssh_key);

-- ------------------------------------------------------------------------------ the constraints
--
-- The `on delete` of each is the one its column already declared; nothing here decides a new
-- policy, it only makes the declared one execute. Where the referencing column has no index MySQL
-- creates one named after the constraint — those are precisely FK lookup columns, so the index is
-- wanted rather than tolerated.

alter table t_scan add constraint fk_scan_repo
    foreign key (repo_id) references t_repository(id) on delete cascade;
alter table t_scan add constraint fk_scan_container
    foreign key (container_id) references t_container(id) on delete cascade;

alter table t_issue add constraint fk_issue_repo
    foreign key (repo_id) references t_repository(id) on delete cascade;
alter table t_issue add constraint fk_issue_container
    foreign key (container_id) references t_container(id) on delete cascade;
alter table t_issue add constraint fk_issue_first_scan
    foreign key (first_seen_scan_id) references t_scan(id) on delete set null;
alter table t_issue add constraint fk_issue_last_scan
    foreign key (last_seen_scan_id) references t_scan(id) on delete set null;

alter table t_finding add constraint fk_finding_scan
    foreign key (scan_id) references t_scan(id) on delete cascade;
alter table t_finding add constraint fk_finding_issue
    foreign key (issue_id) references t_issue(id) on delete set null;

alter table t_component add constraint fk_component_scan
    foreign key (scan_id) references t_scan(id) on delete cascade;
alter table t_ai_review_result add constraint fk_ai_review_scan
    foreign key (scan_id) references t_scan(id) on delete cascade;

alter table t_api_endpoint add constraint fk_api_endpoint_scan
    foreign key (scan_id) references t_scan(id) on delete cascade;
alter table t_api_endpoint add constraint fk_api_endpoint_repository
    foreign key (repository_id) references t_repository(id) on delete cascade;
alter table t_api_contract add constraint fk_api_contract_repository
    foreign key (repository_id) references t_repository(id) on delete cascade;
alter table t_api_contract add constraint fk_api_contract_scan
    foreign key (scan_id) references t_scan(id) on delete cascade;

alter table t_issue_triage_event add constraint fk_triage_event_issue
    foreign key (issue_id) references t_issue(id) on delete cascade;
alter table t_issue_triage_event add constraint fk_triage_event_scan
    foreign key (scan_id) references t_scan(id) on delete set null;

alter table t_session add constraint fk_session_user
    foreign key (user_id) references t_user(id) on delete cascade;
alter table t_user_target add constraint fk_user_target_user
    foreign key (user_id) references t_user(id) on delete cascade;

alter table t_team_member add constraint fk_team_member_team
    foreign key (team_id) references t_team(id) on delete cascade;
alter table t_team_member add constraint fk_team_member_user
    foreign key (user_id) references t_user(id) on delete cascade;
alter table t_team_target add constraint fk_team_target_team
    foreign key (team_id) references t_team(id) on delete cascade;
alter table t_team_webhook add constraint fk_team_webhook_team
    foreign key (team_id) references t_team(id) on delete cascade;

alter table t_agent add constraint fk_agent_api_key
    foreign key (api_key_id) references t_api_key(id) on delete set null;
alter table t_repository add constraint fk_repository_ssh_key
    foreign key (ssh_key_id) references t_ssh_key(id) on delete set null;

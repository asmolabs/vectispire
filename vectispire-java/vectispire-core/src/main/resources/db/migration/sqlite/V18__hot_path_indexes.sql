-- The rest of the indexes the hot paths were reading without.
--
-- V17 covered t_finding because the blast-radius screen made it visible. This is the sweep that
-- followed: every query method in `repositories/` crossed against the thirteen secondary indexes
-- the schema declared. What is below is what the crossing found, and nothing that it did not —
-- each one is traced to the caller named in its comment, because an index added on suspicion is
-- write cost with no reader.
--
-- **A note that explains why so many were missing at once.** Every one of these columns is
-- declared `references t_x(id) on delete cascade` inline, inside the column definition. MySQL
-- parses that form and discards it — no foreign key, no index, and no cascade; only the
-- table-level `foreign key (...) references ...` creates the constraint. PostgreSQL builds the
-- constraint but indexes nothing for it either. So the columns that read like keys were, on both
-- deployable engines, ordinary unindexed integers. The missing cascade is a separate matter and
-- is not repaired here: `TargetDeletionService` already deletes every child table explicitly, so
-- nothing depends on the database to do it.

-- The correlated subquery behind the repository list. `findLatestPerRepository` runs
-- `max(l.id) where l.repo_id = s.repo_id` once per row of t_scan, so an unindexed repo_id makes
-- the page quadratic in the number of scans. `id` trails the key so the max() resolves as an
-- index endpoint rather than an aggregation, and the same key serves `findByRepoId`, the
-- scorecard's `existsByRepoIdAndStatusIgnoreCase` and `countByStatusAndRepoId`. `idx_scan_queue`
-- could not help: it leads with `status`.
create index idx_scan_repo on t_scan(repo_id, id);
create index idx_scan_container on t_scan(container_id, id);

-- The rate limiter reads this table on every login attempt, and it only grows between purges.
-- **A brute-force attempt is when the table is largest and the query most frequent**, so without
-- this the limiter degrades exactly under the load it exists to absorb.
create index idx_login_attempt_key on t_login_attempt(counter_key, occurred_at);

-- `findByIdentifier` is called inside a loop over CVEs by the CycloneDX generator and the VEX
-- ingestor — N scans of t_issue per export, on a table the hot paths already read hardest.
create index idx_issue_identifier on t_issue(identifier);

-- Read on every authenticated request by `VisibilityService`, and the primary key
-- `(team_id, user_id)` cannot answer it in this direction. The table is small; the scan is per
-- request.
create index idx_team_member_user on t_team_member(user_id);

-- Read on every API-key authentication: the CI pipelines and the agents.
create index idx_api_key_prefix on t_api_key(prefix);

-- The four child tables whose principal access is by scan — read with the scan, purged with it by
-- `TargetDeletionService`. Three of them carry an index that cannot serve it: `idx_component_search`
-- leads with `name`, `idx_api_endpoint_repo` with `repository_id`, and `idx_api_contract_repo` does
-- not mention scan_id at all. The fourth carries none.
create index idx_component_scan on t_component(scan_id);
create index idx_api_endpoint_scan on t_api_endpoint(scan_id);
create index idx_api_contract_scan on t_api_contract(scan_id);
create index idx_ai_review_scan on t_ai_review_result(scan_id);

-- The outbox poller's `findDue(status, at)`, on a schedule.
create index idx_outbox_due on t_outbox_message(status, next_attempt_at);

-- `deleteByIssueIdIn`, when an issue and the findings that produced it go together.
create index idx_finding_issue on t_finding(issue_id);

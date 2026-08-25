-- The indexes t_issue never had.
--
-- **This table had none.** The schema declared nine indexes and not one was on the table every
-- hot path reads, while the dimensioning view claimed lookups were indexed on three columns that
-- do not exist under those names. The estimate was published; the index was not.
--
-- Three, each answering a query that runs on a schedule somebody else controls:
--
--   * `(state, repo_id)` and `(state, container_id)` — the quality gate reads one target's open
--     issues on every build of every pipeline, and the compliance summary groups the open backlog
--     by target. Both lead with `state`, which is the selective half on a mature backlog where
--     most rows are resolved.
--   * `(fingerprint)` — the identity of an issue across scans, looked up once per ingested
--     finding. A scan producing two thousand findings did two thousand full scans of this table.
--
-- **Not unique on `fingerprint`, deliberately**, although uniqueness is the real invariant. A
-- unique index would fail this migration on any deployment that already holds a duplicate, and
-- turning an upgrade into an outage to assert an invariant is not the place to assert it. That
-- belongs in a migration that first reports what it would break.

create index idx_issue_state_repo on t_issue(state, repo_id);
create index idx_issue_state_container on t_issue(state, container_id);
create index idx_issue_fingerprint on t_issue(fingerprint);

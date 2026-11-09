-- The OWASP Top 10 grid, recorded per target, per ISO week and per category.
--
-- The grid is computed live from the backlog, the settings and the installed rules. A past week's
-- counts can be approximated from the issues' first and last sightings; its *state* cannot — whether
-- a category was covered, measured or switched off depended on settings and rule sets that have
-- moved since. So the state is recorded as it was read, from the first week this migration runs in:
-- the weeks before it have no state, and a reader must say "not recorded" rather than reconstruct one.
--
-- One row per target (repository or image), week and category, so that a reader can aggregate to a
-- project or a solution and narrow to what they may see. `week_start` is the Monday at 00:00 UTC.
-- `open_count` is what the grid counts — open issues whose triage is not settled; `settled_count` the
-- open issues whose triage is, kept apart so an accepted risk is shown as such rather than dropped or
-- mixed in. Both are zero unless the category was measured: the grid's own rule.
--
-- The target columns are not null because the unique key is the arbiter between two instances
-- rewriting the same week, and a unique key lets as many nulls through as are offered. The key's
-- leading `week_start` serves the reads by week range and the capture's own question (when was this
-- week last written); the second index serves the purge of a deleted target, which names it by kind
-- and identifier.
--
-- Written once, in common: a new table with no foreign key. A deleted target's rows are removed by the
-- `compliance` module's `TargetPurge` listener, in the deleting transaction.

create table t_owasp_weekly_coverage (
    id ${id},
    week_start ${ts} not null,
    target_kind varchar(16) not null,
    target_id bigint not null,
    category varchar(3) not null,
    state varchar(16) not null,
    open_count bigint not null,
    settled_count bigint not null,
    captured_at ${ts} not null,
    constraint uq_owasp_weekly_coverage unique (week_start, target_kind, target_id, category)
);

create index idx_owasp_weekly_coverage_target on t_owasp_weekly_coverage (target_kind, target_id);

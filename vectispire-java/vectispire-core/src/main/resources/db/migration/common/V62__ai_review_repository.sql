-- A model review carries the repository its scan was of.
--
-- The latest review of a repository was a join to `t_scan` for that one column, a query of
-- `compliance` naming `scanning`'s table (`CrossModuleQueriesTest`). Asked through the scans module,
-- it would have been every scan identifier of the repository as an in-list. The repository is copied
-- instead, because it never moves: a scan is created for one target and nothing writes it again, and
-- `fk_ai_review_scan` deletes the review with its scan (V19), so the copy never names a repository
-- the scan did not.
--
-- Filled here from `t_scan` for the rows already stored; `OwaspReviewService` writes it from then on.
-- Null for a review of a scan with no repository, which the join never returned either. Indexed:
-- the report screen asks for one repository's latest on every visit.
--
-- Written once, in common: an added nullable column, an update every engine reads alike, and an index.

alter table t_ai_review_result add column repo_id bigint;

update t_ai_review_result set
    repo_id = (select s.repo_id from t_scan s where s.id = t_ai_review_result.scan_id);

create index idx_ai_review_repository on t_ai_review_result(repo_id, created_at);

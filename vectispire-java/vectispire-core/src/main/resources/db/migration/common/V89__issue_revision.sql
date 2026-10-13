-- An issue's revision, for optimistic locking.
--
-- A scan read the target's issues when its ingestion began and wrote them back whole when it ended;
-- a triage committed in between was overwritten by the values the scan had read — the decision gone,
-- with nothing in the log. A triage read the row and wrote it back whole too, and could put back what
-- a scan had just changed. Each write now names the revision it read, and the second of two writers is
-- refused instead of winning: a triage answers 409 and is made again, a scan reads its issues again and
-- folds once more.
--
-- 0 on every row already stored. Written once, in common: one column whose type every engine spells
-- alike.

alter table t_issue add column revision bigint not null default 0;

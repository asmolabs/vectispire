-- The resolution a reopening ended, on the triage history's entry for it.
--
-- A scan (or an import) that finds a resolved issue again reopens it, and clears a `fixed` triage the
-- return contradicts. That used to leave no entry at all: the history showed a `fixed` decision that had
-- become `under_review` with nothing in between, and the issue's only resolution instant was cleared with
-- it, so nobody could say afterwards that the issue had been resolved from one date to another. The
-- reopening is now an entry of origin `reopen`, actor null, and `previous_resolved_at` is when the
-- resolution it ended began — what lets a reading of the past count the issue as not open from then to
-- the reopening.
--
-- Null on every other entry, and on every row already stored: a reopening before this migration left no
-- entry to carry it.
--
-- Written once, in common: an added nullable column.

alter table t_issue_triage_event add column previous_resolved_at ${ts};

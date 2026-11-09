-- The fingerprint becomes the identity it always was.
--
-- **A fingerprint is what makes an issue the same issue across scans**, and nothing enforced
-- that it appears once. The reconciliation in `IssueSyncService` collects existing rows with
-- `toMap(…, (a, b) -> a)` — a merge function that only ever fires when a fingerprint is already
-- duplicated, so the code has been quietly tolerating what this index now forbids.
--
-- The race that produces one: two scans of the same target overlap, each looks up the
-- fingerprint, each finds nothing, each inserts. The loser is then never refreshed again — it
-- keeps its first-seen date for ever while the winner accumulates the history — and every count
-- in the product tallies it twice.
--
-- **Existing duplicates are merged, not deleted.** A duplicate fingerprint is the same issue by
-- definition, so the oldest row wins: it holds the first-seen date and whatever triage history
-- exists. The children are repointed at it *before* the losers are removed, because both child
-- tables cascade on delete and a triage decision recorded against the wrong twin would otherwise
-- disappear with it.
--
-- **What this changes at runtime, stated rather than discovered later:** the race now ends in a
-- constraint violation and a failed scan instead of a silent duplicate. That is the trade taken
-- deliberately — a failed scan is visible and repeatable, a duplicated issue is neither.

-- Repoint every child at the surviving twin.
update t_issue_triage_event
   set issue_id = (select min(survivor.id) from t_issue survivor
                    where survivor.fingerprint =
                          (select duplicate.fingerprint from t_issue duplicate
                            where duplicate.id = t_issue_triage_event.issue_id))
 where issue_id is not null;

update t_issue_ticket
   set issue_id = (select min(survivor.id) from t_issue survivor
                    where survivor.fingerprint =
                          (select duplicate.fingerprint from t_issue duplicate
                            where duplicate.id = t_issue_ticket.issue_id))
 where issue_id is not null;

update t_finding
   set issue_id = (select min(survivor.id) from t_issue survivor
                    where survivor.fingerprint =
                          (select duplicate.fingerprint from t_issue duplicate
                            where duplicate.id = t_finding.issue_id))
 where issue_id is not null;

-- The derived table is not decoration: MySQL refuses a subquery that reads the table being
-- deleted from, and wrapping it is the portable way to say the same thing.
delete from t_issue
 where id not in (select keep from (select min(id) as keep from t_issue group by fingerprint) survivors);

-- The plain index from V15 is subsumed by the unique one; keeping both would mean two structures
-- maintained on every write for one lookup.
drop index idx_issue_fingerprint on t_issue;
create unique index uq_issue_fingerprint on t_issue(fingerprint);

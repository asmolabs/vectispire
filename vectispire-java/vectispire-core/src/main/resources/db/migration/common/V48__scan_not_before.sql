-- A scan whose attempt could not run waits before it can be claimed again.
--
-- A remote agent that reported a scan it could not run took it back at its next poll, a few seconds
-- later — alone in its pool, it was the only executor asking — and the three attempts meant to
-- outlast a passing incident were spent before the incident had passed. `not_before` is the instant
-- a waiting scan becomes claimable: the failure's, plus one minute after the first attempt, five
-- after the second, fifteen after any later one (`vectispire.queue.retry-delays`). The claim skips a
-- scan whose `not_before` is still ahead, on every engine; a lapsed lease sets it as a report does.
--
-- Null on every row already stored, and null means "claimable now": the scans waiting at the upgrade
-- keep their place in the queue.
--
-- Written once, in common: an added nullable column.

alter table t_scan add column not_before ${ts};

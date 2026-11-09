-- The status a decision waiting for a second person asked for, kept beside the queue.
--
-- A settling decision by somebody who cannot approve is queued as `pending_approval`, and the status
-- it asked for — `not_affected`, `will_not_fix` or `fixed` — was dropped there: neither the issue nor
-- its history recorded it. The approver then chose a status of their own, and a tracker's "Won't Fix"
-- could be granted as `not_affected`, which the signed VEX documents state as "not exposed" (decision
-- 0041). The issue now carries the request while it waits, and the history row that queued it says
-- what was asked; an approval grants that status or is refused.
--
-- Null on every row already stored: nobody recorded what those requests asked for, and guessing it from
-- the justification would write down the very assumption this corrects. Such a request is granted as
-- the approver chooses, as before.
--
-- Written once, in common: two nullable columns, of a type every engine spells alike.

alter table t_issue add column triage_requested_status varchar(30);

alter table t_issue_triage_event add column requested_status varchar(30);

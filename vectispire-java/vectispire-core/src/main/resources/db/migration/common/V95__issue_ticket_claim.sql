-- The ticket sweep's claim on an issue, before it asks the tracker for a ticket.
--
-- Every instance runs every maintenance task (`MaintenanceTask`: no leader election there), and a task that
-- delivers something must claim each item first, as the outbox relay does. The sweep did not: two instances
-- whose hourly passes overlapped both read an issue with no `ticket_ref`, both asked the tracker, and a tracker
-- does not deduplicate — the issue got two tickets where one is promised.
--
-- `ticket_claimed_by` names the instance holding the claim, `ticket_claim_until` when it lapses: taken by a
-- conditional update before the tracker is asked, cleared when the reference is attached or the attempt fails,
-- and taken over once lapsed — an instance that died between the claim and the reference. Null on every existing
-- row: nothing is claimed.
--
-- Written once, in common: two nullable columns, typed by the placeholders.

alter table t_issue add ticket_claimed_by varchar(64);

alter table t_issue add ticket_claim_until ${ts};

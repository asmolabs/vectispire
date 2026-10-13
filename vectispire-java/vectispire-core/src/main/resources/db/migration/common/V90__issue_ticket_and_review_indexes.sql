-- The two issue columns looked up with nothing to find them by.
--
-- `ticket_ref`: the anonymous tracker webhook looks its issues up by reference at every delivery, and
-- the hourly sweep picks the open issues that carry none (`ticket_ref is null`); both read the whole
-- of t_issue. `triage_expires_at`: the maintenance tick asks for the decisions whose review date has
-- passed (`triage_expires_at <= now`), the whole table again, every tick.
--
-- Both columns take a plain index on both engines: `ticket_ref` is a varchar(64) — 256 bytes in
-- utf8mb4, far under InnoDB's key limit, no prefix needed — and `triage_expires_at` a datetime(6) or a
-- timestamp with time zone. A null is indexed on both, so `is null` is served too.
--
-- Written once, in common: the statements are the same on both engines.

create index idx_issue_ticket_ref on t_issue(ticket_ref);

create index idx_issue_triage_expires_at on t_issue(triage_expires_at);

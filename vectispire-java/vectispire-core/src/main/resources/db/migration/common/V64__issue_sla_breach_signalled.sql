-- When the SOC was told that an issue passed its remediation deadline.
--
-- The hourly maintenance turn forwards an SLA breach to the SIEM once per issue (`VECTI-SEC-030`);
-- `sla_breach_signalled_at` is what makes it once. Set when the crossing is noticed — whether or not
-- an export was configured to carry it, since an event nobody was listening for is not replayed
-- later — and never cleared: a resolved issue that comes back keeps its first sighting, so its
-- deadline and its breach are the ones already announced.
--
-- Null on every row already stored. The turn only announces deadlines that passed within the last
-- seven days, so the backlog already late at the upgrade is not announced all at once.
--
-- Written once, in common: an added nullable column.

alter table t_issue add column sla_breach_signalled_at ${ts};

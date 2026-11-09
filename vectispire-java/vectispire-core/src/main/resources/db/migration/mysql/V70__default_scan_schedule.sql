-- "Manual only" becomes a choice, and "no schedule" becomes the installation's default (0.11.0).
--
-- Until now a target with neither an interval nor a cron expression was never rescanned, and that is
-- what the add forms produced: most targets were examined once. From this version such a target is
-- rescanned on the default interval (the `scan_default_interval_days` setting, a week unless an
-- administrator changes it), and an operator who wants no rescan sets `scan_manual_only`. A flag of
-- its own rather than "interval 0 means manual, null means default": the API has always read an
-- interval of zero as "clear it", rows already hold zeros written that way, and a state that only
-- shows as the difference between two spellings of "nothing" is one nobody reading a row can see.
--
-- **Nobody's earlier wish for "manual" can be told apart from "never set"**, so every existing
-- target without a schedule moves to the default — the product owner's intent, said in the release
-- notes with the way back (set "manual only").
--
-- **Stamped with the upgrade, so that the first round is spread.** The default's rounds fall at a
-- moment of each target's own in the interval (`Schedules.defaultDue`), and a target never picked up
-- is due at once — which, left alone, would make the whole estate due in the first minute after the
-- upgrade. Recording the upgrade as each one's last scheduled round makes its first round its own
-- moment in the following interval instead. `last_scheduled_scan_at` of those targets therefore reads
-- as the upgrade until their first round; no scan is recorded by it, and nothing reads it as one.
--
-- Written once per engine because "now, in UTC" is spelled differently: here `utc_timestamp(6)`, the column
-- being a `datetime(6)` holding UTC.

alter table t_repository add column scan_manual_only boolean not null default false;
alter table t_container add column scan_manual_only boolean not null default false;

update t_repository set last_scheduled_scan_at = utc_timestamp(6)
where coalesce(scan_interval_minutes, 0) <= 0 and (scan_cron is null or trim(scan_cron) = '');
update t_container set last_scheduled_scan_at = utc_timestamp(6)
where coalesce(scan_interval_minutes, 0) <= 0 and (scan_cron is null or trim(scan_cron) = '');

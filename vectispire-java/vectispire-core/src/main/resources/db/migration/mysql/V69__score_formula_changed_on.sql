-- The day this installation's grades changed formula (decision 0036, 0.11.0), for the dashboard's trend
-- chart to mark: a reader comparing a period across it has to see that the grades moved because the
-- arithmetic did, not because the estate got worse.
--
-- **This installation's day, not the release's.** An installation upgrading a month after 0.11.0 was
-- published kept the old grades for that month; a line drawn at the release date would put the change
-- a month early on its chart. The migration runs at the upgrade, so the date it writes is when the
-- grades actually changed here.
--
-- **Only where there were grades to change.** A fresh installation, or one that never completed a scan,
-- has never shown a grade under the old formula: it gets no row, and no line marks a change nobody saw.
--
-- An internal row (`SettingsService.internalValue`): no setting of the catalogue names it, so the
-- settings screen neither shows nor edits it. ISO date, UTC, as the chart's axis. Written once per
-- engine because the two spell "today's date as text" differently.

insert into t_setting (`key`, value)
select 'internal.scorecard_formula_changed_on', date_format(utc_date(), '%Y-%m-%d') from dual
where exists (select 1 from t_scan where status = 'completed');

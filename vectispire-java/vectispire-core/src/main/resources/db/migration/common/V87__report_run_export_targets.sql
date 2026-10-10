-- The targets a report run's export carried, recorded with the run (decision 0042).
--
-- A produced document was served to whoever saw the project whole at the time of the download. A
-- project's targets move: a repository taken out of it after the run left its findings in the document,
-- readable by a reader who sees the project as it is now and was never shown that repository. The run now
-- records what its export was built over, and the document is served to a reader who sees every one of
-- those targets as well as the project.
--
-- Space-separated, in the form an issue's fingerprint names a target (`repo:12 container:4`). Null on the
-- runs from before this migration — nobody recorded what they carried, and filling the column from the
-- projects' current targets would write down exactly the assumption this corrects; their documents are
-- served to a reader who sees everything. Empty for an export built over a project holding no target.
--
-- Written once, in common: a nullable column added to one table.

alter table t_report_run add column export_targets ${text};

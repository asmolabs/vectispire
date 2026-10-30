-- The scan history, newest first, read from an index instead of sorted.
--
-- `GET /api/v1/scans` and the dashboard's recent scans read `t_scan` ordered by `created_at desc, id desc`
-- with a limit. With no index on that order MySQL sorted the whole table to keep fifty rows — and since
-- 8.0.20 its filesort carries the selected columns, the SBOM among them: every scan's document was read to
-- answer a page. 480 to 580 ms a call on the 1.0.0-rc.1 load test's estate (900 scans of 340 KB), growing
-- with the SBOMs kept; 5 ms with this index, which the engine walks backwards and stops after the page.
--
-- Written once, in common: the same statement on both engines.

create index idx_scan_created on t_scan (created_at, id);

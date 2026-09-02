-- The indexes t_finding never had.
--
-- **This table has none but its primary key**, and it is the largest one in the schema — the
-- dimensioning view estimates half a million rows. `scan_id` is declared with an inline
-- `references`, which reads like a foreign key and is not one on any of the three engines: MySQL
-- parses column-level `references` and discards it, Postgres builds the constraint but indexes
-- nothing for it, SQLite likewise. So the column every read of this table joins on was unindexed
-- on all three, and it read that way in none of them.
--
-- Two, each answering a query somebody waits on:
--
--   * `(scan_id)` — the join in every finding read: the scan detail page, the graph queries, the
--     ingest that reconciles a new scan against the last. Without it a lookup of one scan's
--     findings is a scan of the whole table.
--   * `(package_name)` — the group key of the blast-radius top-impact list, which runs on every
--     open of that screen. The aggregate still visits every row, since that is what an estate-wide
--     grouping is; the index is what lets the engine visit them in group order instead of
--     materializing a temporary table of the whole thing.
--
-- Neither is unique, and neither should be: a scan holds many findings, and a package appears in
-- as many as it is depended on by. That multiplicity is the thing being counted.

create index idx_finding_scan on t_finding(scan_id);
create index idx_finding_package on t_finding(package_name);

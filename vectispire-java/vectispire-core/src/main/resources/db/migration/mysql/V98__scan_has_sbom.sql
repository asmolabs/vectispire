-- Whether a scan holds its SBOM, as a column of its own, so that asking does not read the document.
--
-- Ten queries asked `sbom is null` or `sbom is not null` — the licence tallies' census, the inventory's
-- scans, the newest completed scan of each target the posture and the scorecards read. InnoDB keeps a
-- long `longtext` off the row, and testing it for null reads it back all the same: each of those
-- queries read every SBOM stored, 500 ms a statement on the 1.0.0-rc.1 load test's estate (900 scans of
-- 340 KB, 300 MB), twice per licence, scorecard and posture call, and in proportion to the SBOMs an
-- installation keeps — a real one's run to megabytes. A count over the same rows by `status` took 0.3 ms.
--
-- **Generated and stored, so nothing has to keep it.** The engine computes it at each write of `sbom` —
-- the ingestion, the retention purge's bulk `set sbom = null`, a build SBOM's import — and the queries
-- read the flag instead of the document (`ScanEntity.hasSbom`, mapped read-only). Adding a stored
-- generated column rebuilds the table once, reading each SBOM one last time: 2.4 s for the load test's
-- 300 MB, measured on MySQL 9.4; proportionally longer on a larger installation, at the upgrade's start.
--
-- `bit(1)`, the type Hibernate maps a boolean to on this engine (`MigrationDialect`). Written twice, since
-- a generated column's syntax is the engines' own (decision 0027): PostgreSQL's is beside this one.

alter table t_scan add column has_sbom bit(1) generated always as (sbom is not null) stored;

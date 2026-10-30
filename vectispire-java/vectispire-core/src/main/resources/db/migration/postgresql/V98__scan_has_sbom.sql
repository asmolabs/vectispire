-- Whether a scan holds its SBOM, as a column of its own, so that asking does not read the document.
--
-- The reasoning is MySQL's migration of the same version: ten queries tested `sbom` for null, and InnoDB
-- read every stored SBOM to answer them (1.0.0-rc.1 load test). PostgreSQL answers a null test from the
-- tuple's null bitmap without detoasting, so the column changes little here — but the queries are the
-- same JPQL on both engines and read `ScanEntity.hasSbom`, so the column exists on both.
--
-- Generated and stored: computed at each write of `sbom`, kept by nothing in the application. Written
-- twice, since a generated column's syntax is the engines' own (decision 0027).

alter table t_scan add column has_sbom boolean generated always as (sbom is not null) stored;

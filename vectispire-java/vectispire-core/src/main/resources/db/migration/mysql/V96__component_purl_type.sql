-- A component's package-URL type (`pkg:npm/`) as a column of its own, indexed with the component's target.
--
-- Rule coverage reads of the inventory only which ecosystems each target is written in. The gate asks it of
-- the target in front of it at every verdict, the dashboard, the security overview and the OWASP grid of
-- every target at every call; each read the whole of `t_component` — a row per package per scan, never
-- purged. On the 1.0.0-rc.1 load test's estate (300 targets, a million rows) a gate call took 1.8 s and
-- the dashboard 2.9 s, and the estate's question still took 350 ms once asked of the purl's prefix.
--
-- **Generated and stored, so nothing has to keep it**: the engine computes it at each write of `purl`,
-- the build-SBOM completion's update in place included. The index then answers each question without
-- reading a row: a target's types by its prefix (`repo_id = ?`, or `repo_id is null and container_id = ?`),
-- and the estate's by a loose index scan — one entry per target and type, 1,500 on that estate, rather
-- than the million (350 -> 40 ms). `ComponentRepository.distinctPurlTypes…` read it.
--
-- The value is the purl up to and including its first slash, empty when it has none and null with the
-- purl — exactly what `RuleCoverage` read of a purl, so the answers do not move. A varchar(500) as the
-- purl is, so no purl can fail to fit; 2,018 bytes of key in utf8mb4 with the two ids, under InnoDB's
-- 3,072. Adding a stored generated column rebuilds the table: 8.9 s for the million rows, plus 1 s for
-- the index, measured on MySQL 9.4 — at the upgrade's first start, in proportion to the inventory kept.
--
-- Written twice, since a generated column's syntax is each engine's own (decision 0027).

alter table t_component
    add column purl_type varchar(500) generated always as (substring(purl, 1, locate('/', purl))) stored;

create index idx_component_target_purl_type on t_component (repo_id, container_id, purl_type);

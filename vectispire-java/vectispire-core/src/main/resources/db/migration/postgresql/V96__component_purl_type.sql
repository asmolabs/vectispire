-- A component's package-URL type (`pkg:npm/`) as a column of its own, indexed with the component's target.
--
-- The reasoning is MySQL's migration of the same version: rule coverage reads only which ecosystems each
-- target is written in, and every gate verdict, dashboard and security overview read the whole inventory
-- to answer it (1.0.0-rc.1 load test). The value is the purl up to and including its first slash, empty
-- when it has none and null with the purl, as MySQL's `substring(purl, 1, locate('/', purl))` is:
-- `position` answers 0 for no slash, and a substring of length 0 is empty.
--
-- Generated and stored: computed at each write of `purl`, kept by nothing in the application. Written
-- twice, since a generated column's syntax is each engine's own (decision 0027).

alter table t_component
    add column purl_type varchar(500) generated always as (substring(purl from 1 for position('/' in purl))) stored;

create index idx_component_target_purl_type on t_component (repo_id, container_id, purl_type);

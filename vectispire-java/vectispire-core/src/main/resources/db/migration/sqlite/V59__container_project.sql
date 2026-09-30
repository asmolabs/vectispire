-- A container image may be filed in a project, like a repository (decision 0023, amendment of
-- 2026-09-30 "containers join projects").
--
-- A nullable column on t_container, for the reason V39 gave the repository one: a figure or a report
-- must add up to one project without double counting, and "which project is this image in" must have
-- one answer. Existing images start in no project; nothing is inferred from a registry or a name.
-- Deleting a project detaches its images (set null) as it detaches its repositories; the service does
-- it explicitly and the key is the backstop.
--
-- Written three times, not in common: the foreign key is the structure that diverges.

-- SQLite cannot add a constraint to an existing table, but accepts a REFERENCES on a column added with
-- no default, which is what V39 did for t_repository.
alter table t_container add column project_id bigint references t_project(id) on delete set null;
create index idx_container_project on t_container (project_id);

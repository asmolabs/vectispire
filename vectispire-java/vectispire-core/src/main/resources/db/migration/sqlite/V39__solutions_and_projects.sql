-- Solutions contain projects; a project references repositories (decision 0023).
--
-- A repository belongs to at most one project, so the link is a nullable column on t_repository
-- and not a link table: a figure or a report must add up to one project without double counting,
-- and "which project is this in" must have one answer. Existing repositories start with no
-- project — nothing is inferred from names or URLs; an administrator files them.
--
-- Deleting a project detaches its repositories (set null) and deletes none of them. Deleting a
-- solution that still holds projects is refused by the service; the restrict here is the
-- backstop, so that a project created in another tab cannot be left pointing at nothing.

create table t_solution (
    id integer primary key autoincrement,
    name varchar(100) not null,
    description varchar(255),
    created_at numeric not null,
    constraint uq_solution_name unique (name)
);

-- Inline, because SQLite has no `alter table … add constraint`: a key that is not in the
-- `create table` never exists on this engine.
create table t_project (
    id integer primary key autoincrement,
    solution_id bigint not null references t_solution(id) on delete restrict,
    name varchar(100) not null,
    description varchar(255),
    created_at numeric not null,
    constraint uq_project_solution_name unique (solution_id, name)
);

alter table t_repository add column project_id bigint references t_project(id) on delete set null;
create index idx_repository_project on t_repository (project_id);

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
--
-- Names are unique case-insensitively, which the service checks: MySQL's collation folds case in
-- a unique constraint and PostgreSQL's does not, and a rule that depends on the engine is not a
-- rule. The constraints below catch the race the service cannot.

create table t_solution (
    id bigint auto_increment primary key,
    name varchar(100) not null,
    description varchar(255),
    created_at datetime(6) not null,
    constraint uq_solution_name unique (name)
);

create table t_project (
    id bigint auto_increment primary key,
    solution_id bigint not null,
    name varchar(100) not null,
    description varchar(255),
    created_at datetime(6) not null,
    constraint uq_project_solution_name unique (solution_id, name)
);

-- Named and separate: MySQL parses a column-level REFERENCES and then ignores it (see V19, V36).
alter table t_project add constraint fk_project_solution
    foreign key (solution_id) references t_solution(id) on delete restrict;

alter table t_repository add column project_id bigint;
-- Declared before the key so MySQL adopts it rather than creating one of its own: visibility
-- resolves a project grant through this column on every request a project grantee makes.
create index idx_repository_project on t_repository (project_id);
alter table t_repository add constraint fk_repository_project
    foreign key (project_id) references t_project(id) on delete set null;

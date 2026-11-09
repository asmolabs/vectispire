-- Where an imported target came from — decision 0037 §5, lot D6: the provenance of a repository target created
-- by an import from a forge connection's discovery.
--
-- Written once, in common: a new table, no foreign key in or out. It belongs to the `forges` module, and a key
-- into `t_repository` would be a key into another module's table: the module listens to `TargetDeleted` and
-- deletes the target's link in the deleting transaction instead, as decision 0035's tables listen to
-- `ProjectDeleted`. Deleting a connection deletes its links and no target.
--
-- `(connection_id, forge_id)` is unique: a repository of a connection is imported once, and a renamed or moved
-- repository is still recognised by the forge's id, which a rename keeps. `repository_id` is unique too: a target
-- came from one place. `discovery_id` names the run whose snapshot the import read, `imported_by` who asked.
create table t_forge_import_link (
    id ${id},
    repository_id bigint not null,
    connection_id char(36) not null,
    forge_id varchar(64) not null,
    discovery_id bigint not null,
    imported_at ${ts} not null,
    imported_by varchar(255) not null,
    constraint uq_forge_import_link unique (connection_id, forge_id),
    constraint uq_forge_import_link_repository unique (repository_id)
);

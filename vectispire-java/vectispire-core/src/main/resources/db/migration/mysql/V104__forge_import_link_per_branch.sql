-- A forge repository may now be imported as several targets, one per branch — decision 0037 §5: `master` and
-- `develop` of one repository scanned apart. V78 held `(connection_id, forge_id)` unique, a repository of a
-- connection imported once; that key goes, and an index on the same columns keeps the lookups it served.
--
-- What it guarded is guarded elsewhere: two imports of one branch of one repository racing meet on the target's own
-- unique guard (V73, the URL's identity, the branch and the sub-path), which is the key the import's retry reads; a
-- target still comes from one place (`uq_forge_import_link_repository` stays).
--
-- Written twice: a unique key is an index dropped by name on MySQL and a constraint on PostgreSQL.
create index idx_forge_import_link_forge on t_forge_import_link (connection_id, forge_id);
alter table t_forge_import_link drop index uq_forge_import_link;

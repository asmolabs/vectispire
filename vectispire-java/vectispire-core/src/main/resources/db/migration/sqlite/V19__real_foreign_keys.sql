-- Nothing a migration can do here, and that is the point of the file.
--
-- SQLite records the inline `references t_x(id) on delete …` declarations — they are in the
-- schema and always have been — but it **enforces none of them unless the connection has issued
-- `PRAGMA foreign_keys = ON`**. The pragma is per connection, so it belongs to how the pool opens
-- one, not to a migration; it is set on the datasource, and `ForeignKeyEnforcementTest` is what
-- checks it stayed set.
--
-- Nor could a migration add the constraints if the pragma were absent: SQLite has no
-- `alter table … add constraint`. Changing a table's constraints means rebuilding it and copying
-- its rows, which is not a thing to do to `t_finding` on a running deployment to fix something the
-- pragma fixes for free.
--
-- The orphan sweep the MySQL V19 performs is not repeated for the same reason it is safe there:
-- with the pragma on, the engine has been refusing orphans since the connection was opened.

select 1;

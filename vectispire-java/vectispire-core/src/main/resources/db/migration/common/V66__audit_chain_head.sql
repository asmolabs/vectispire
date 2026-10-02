-- One row every audit entry locks before it chains onto the log's head.
--
-- An entry reads the chain's newest entry and inserts itself onto it, in a short transaction of its
-- own. The read took no lock and nothing made `previous_hash` unique, so two writers that read the
-- same head before either committed both chained onto it: a fork, which the verification reports as a
-- break in a log nobody touched — an "audit chain broken" alarm and a SIEM event for nothing.
-- `AuditChainConcurrencyIntegrationTest` produced forks on MySQL and PostgreSQL alike, from eight
-- threads of one instance and from two instances over one table (2026-10-02).
--
-- `select … for update` on this row serialises the writers, across instances too since the lock is
-- the database's. A row of its own rather than a lock on the newest entry: an empty log has no newest
-- entry to lock, and the head moves with every write.
--
-- Written once, in common: the same table on both engines.

create table t_audit_chain_head (
    id integer not null primary key
);

insert into t_audit_chain_head (id) values (1);

-- Nothing to do here, and the reason is worth a file rather than an absence.
--
-- The MySQL V19 makes twenty-four inline `references t_x(id) on delete …` declarations into real
-- constraints, because MySQL parses that form and discards it. **PostgreSQL does not**: it builds
-- the constraint from the inline form, cascade included. Verified against the engine rather than
-- read in a manual — `pg_constraint` reports the key with `confdeltype = 'c'` for a column written
-- exactly as this schema writes them.
--
-- What PostgreSQL does *not* create is an index on the referencing column. That half was real and
-- was repaired in V18.
--
-- This file exists so the versions line up across the three migration locations and so the next
-- person to compare them finds the answer here instead of concluding the engine was forgotten.

select 1;

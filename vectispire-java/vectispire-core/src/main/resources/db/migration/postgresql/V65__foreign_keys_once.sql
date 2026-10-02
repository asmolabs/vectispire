-- Nothing to do here, as for V19, and for the same reason.
--
-- The MySQL V65 settles two things the two MySQL majors read differently in a column-level
-- `references`: the twin keys MySQL 9 builds beside V19's named ones, and `t_mfa_challenge.user_id`,
-- which V23 declared inline and MySQL 8 therefore never constrained. PostgreSQL has always built the
-- constraint from the inline form, once, so neither exists here: `t_mfa_challenge_user_id_fkey`
-- carries the cascade, and there is no second key to drop.
--
-- This file exists so the version lines up across both engines' locations.

select 1;

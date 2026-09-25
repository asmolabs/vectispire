-- The last TOTP time step an account has used, so that a code opens one session and not two.
--
-- A code was accepted for as long as its ±30 s window lasted, however many times it was
-- presented: read over a shoulder or captured on the wire, it opened a second session within the
-- minute. A step is accepted only when it is later than this one, and the comparison is made by
-- the update that records it, so two presentations racing each other cannot both win.
--
-- Null until the account next uses a code; enrolment records the step of the code that proved it.

alter table t_user add column totp_last_step bigint;

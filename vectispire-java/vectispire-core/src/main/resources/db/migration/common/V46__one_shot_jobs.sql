-- The jobs that run once per database, and the row that says one has.
--
-- Written once, in common: a new table with no foreign key. The repair of the attempts withheld
-- claims counted was kept once by its audit entry alone: it ran while no entry existed, so two
-- instances starting together both read none, both ran, and both wrote one. The primary key is the
-- arbitration now: the job's first statement inserts its name, in the transaction that does the
-- work, and the second instance's insert waits for the first to commit and fails — one run, one
-- entry. `ran_at` is when it was claimed, for whoever asks why a job did not run again.
create table t_one_shot_job (
    name varchar(64) not null primary key,
    ran_at ${ts} not null
);

-- How changes reach a repository's branch, as its forge said — decision 0037, lot G3: the evidence of the
-- checklists' change_review rule, read hourly through the forge connection that imported or discovered the
-- repository, and kept per repository and branch for the rule to read without calling the forge.
--
-- Written once, in common: a new table, no foreign key in or out. It belongs to the `forges` module; a key into
-- `t_repository` would be a key into another module's table, so the module deletes a target's readings when it
-- hears `TargetDeleted`, and a connection's when it is deleted.
--
-- `wanted_branch` is the rule's branch, '' for the default branch the forge names — not null, so that the unique
-- key holds on every engine (MySQL lets two nulls share one). `state` is pending (claimed, never read), read,
-- unreadable (the forge refused, `reason` says why) or unlinked (no connection knows the repository). `evidence`
-- is the reading as the rule reads it, `evidence_sha256` its digest — what the checklist line names as its look.
-- `claimed_until` is the claim of the instance reading it: every instance runs the hourly task, one reads.
create table t_forge_review_reading (
    id ${id},
    repository_id bigint not null,
    wanted_branch varchar(255) not null,
    state varchar(20) not null,
    connection_id char(36),
    forge_id varchar(64),
    window_days integer not null,
    read_at ${ts},
    reason varchar(1000),
    evidence ${text},
    evidence_sha256 varchar(64),
    claimed_until ${ts},
    constraint uq_forge_review_reading unique (repository_id, wanted_branch)
);

-- The accounts a project's checklist profiles are linked to — decision 0044.
--
-- A profile is a value of the template's contact column ("PO", "Arch"), keyed as `ContactProfiles` keys
-- it: normalised and upper-cased, so "Arch" and "ARCH" are one row. One account per profile and
-- project: the unique key is what a second link replaces, and two people linking at once leave one
-- row, the later one.
--
-- Written once, in common, and with no foreign key, like every checklist table (V52): a project's rows
-- are purged by the `checklists` module's listener in the transaction that deletes it (`ProjectDeleted`).
-- `account_id` names an account that may be deleted later — through SCIM, which deletes the row — and
-- then names nobody: the profile reads as linked to an account that no longer exists, and its lines go
-- to the CISOs until somebody links it again. A key with `on delete set null` would say the same thing
-- less visibly, and would have to be written once per engine.
--
-- The profile's key is kept rather than a template item's id: a link outlives the version it was made
-- on, and the next version's column names the same profiles.
create table t_checklist_contact (
    id ${id},
    project_id bigint not null,
    profile varchar(255) not null,
    account_id bigint not null,
    linked_by varchar(255) not null,
    linked_at ${ts} not null,
    constraint uq_checklist_contact unique (project_id, profile)
);

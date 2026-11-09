-- Who administered which account, and the account changes waiting for a second administrator (#126,
-- options 1 and 2).
--
-- **`t_account_administration`: who created an account, reset its password or changed its role, and
-- when.** Under four-eyes an approval is refused when the requester did one of those to the approver's
-- account recently (`ApproverIndependence`): the second identity an approval needs could otherwise be one
-- the requester made, or one whose password the requester typed. The audit trail records the same
-- gestures, but as `USER_UPDATED` entries whose description says which — "Account created", "role A → B",
-- "password reset" — and a guard reading a sentence stops guarding the day the sentence is reworded. A
-- row per gesture rather than a column per kind on `t_user`: a column keeps the last administrator only,
-- and a reset by somebody else would hide the requester's own a week earlier.
--
-- Empty after the upgrade: the gestures of the weeks before it are in the audit log only, and are not
-- read back from its sentences, for the reason above.
--
-- **`t_account_request`: an account change filed under four-eyes and not yet decided.** Creating an
-- account with an approving role, raising a role to one, or resetting the password of an account that
-- holds one waits here for a second administrator. `password_hash` is the hash of the temporary password
-- the requester typed, never the password: the approver applies it without seeing it, and the account
-- must change it at its next sign-in as after any reset.
--
-- Both keys cascade: a request about an account that is deleted asks for nothing, and one whose
-- requester is deleted has nobody left to stand behind it. Written twice, with the PostgreSQL file beside
-- this one, since a foreign key is the engines' own (decision 0027); named and separate, as MySQL ignores
-- a column-level REFERENCES (see V19, V36).

create table t_account_administration (
    id ${id},
    account_id bigint not null,
    administrator_id bigint not null,
    gesture varchar(32) not null,
    -- The role the account held before the gesture: a role change out of an administrative role is what
    -- keeps an administrator who lowered the others from counting as alone.
    held_role varchar(32),
    occurred_at ${ts} not null
);
-- Declared before the keys, so that MySQL adopts it rather than creating one of its own: every approval
-- under four-eyes asks it for one account and one administrator.
create index idx_account_administration_lookup
    on t_account_administration (account_id, administrator_id, occurred_at);
alter table t_account_administration add constraint fk_account_administration_account
    foreign key (account_id) references t_user(id) on delete cascade;
alter table t_account_administration add constraint fk_account_administration_administrator
    foreign key (administrator_id) references t_user(id) on delete cascade;

create table t_account_request (
    id ${id},
    kind varchar(16) not null,
    status varchar(16) not null,
    account_id bigint,
    username varchar(255) not null,
    email varchar(255),
    display_name varchar(255),
    held_role varchar(32),
    requested_role varchar(32),
    password_hash varchar(255),
    requested_by_id bigint not null,
    requested_by varchar(255) not null,
    requested_at ${ts} not null,
    decided_by varchar(255),
    decided_at ${ts}
);
create index idx_account_request_status on t_account_request (status, requested_at);
alter table t_account_request add constraint fk_account_request_account
    foreign key (account_id) references t_user(id) on delete cascade;
alter table t_account_request add constraint fk_account_request_requester
    foreign key (requested_by_id) references t_user(id) on delete cascade;

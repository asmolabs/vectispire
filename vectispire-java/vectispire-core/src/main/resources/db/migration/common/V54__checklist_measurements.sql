-- A checklist line's measurements — decision 0032 §1 and §6.
--
-- Written once, in common: one new table, no foreign key. Every row names a checklist, and the
-- `checklists` module's listener purges them with the project's checklists (`ProjectDeleted`, open
-- question 10), before the checklists they are found through.
--
-- A measurement is what a rule found, at one instant, for one line of one revision: the outcome
-- (`pass`, `fail`, `no_data`), the reason when there is no data, the instant it is as of — its oldest
-- evidence — and the evidence as it was judged, with the digest of that text. It is stored when it is
-- relied on: when a person's answer rests on it (`answer`), at the submission (`submission`), and
-- inside the sign-off (`sign_off`), which freezes the revision's measurements with it. A measurement
-- read on screen is computed and not stored.
--
-- `bound_rule` is the rule's canonical form, as the item held it, and `rule_digest` its SHA-256: what
-- was applied is kept beside what it found, so that the measurement reads the same once the template
-- has moved on. `answer_id`, `answer_value` and `reconciliation` are the answer it was reconciled with
-- at a submission or a sign-off, and what the two said together (`consistent`, `contradicted`,
-- `declared_not_measured`, …) — the divergence recorded, not only shown.
create table t_checklist_measurement (
    id ${id},
    checklist_id bigint not null,
    item_id bigint not null,
    purpose varchar(20) not null,
    rule_kind varchar(40) not null,
    rule_digest varchar(64) not null,
    bound_rule ${text} not null,
    outcome varchar(10) not null,
    reason varchar(40),
    as_of ${ts},
    computed_at ${ts} not null,
    computed_by varchar(255) not null,
    answer_id bigint,
    answer_value varchar(20),
    reconciliation varchar(30),
    evidence_digest varchar(64) not null,
    evidence ${text} not null
);

create index idx_checklist_measurement_line on t_checklist_measurement (checklist_id, item_id);

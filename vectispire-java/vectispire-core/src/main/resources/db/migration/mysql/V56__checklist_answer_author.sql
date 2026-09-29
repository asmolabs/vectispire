-- Who wrote a checklist answer: a person, or Vectispire itself — decision 0032, amendment "the scans
-- answer the lines they measure" (2026-09-29).
--
-- Written three times, not in common: an answer by Vectispire belongs to no account, so
-- `answered_by_id` stops being `not null`, and a column's nullability is changed differently on each
-- engine — SQLite cannot change it at all and rebuilds the table.
--
-- `answered_by_kind` is the distinction, and it is structural on purpose: `answered_by` is a name, and
-- an account may be called "Vectispire" — usernames are free text. `person` for every row written
-- before, and for every answer a person gives; `system` for one Vectispire wrote from a measurement,
-- which names no account. The check keeps the two apart: a person's answer names its account, the
-- system's names none, and a system row can never pass for a person's by carrying an id. MySQL
-- enforces a check constraint from 8.0.16 on — the composition ships 8, the campaign runs 9.
--
-- `withdrawn` marks the row by which Vectispire withdraws its own answer when the measurement it
-- rested on no longer has data: the table stays append-only, the line's current answer becomes none,
-- and the history keeps both. Only the system withdraws, which the check states too — a person
-- replaces an answer by giving another.
alter table t_checklist_answer
    add column answered_by_kind varchar(10) not null default 'person',
    add column withdrawn bit(1) not null default b'0',
    modify column answered_by_id bigint null;
alter table t_checklist_answer add constraint ck_checklist_answer_author check (
    (answered_by_kind = 'person' and answered_by_id is not null and withdrawn = b'0')
    or (answered_by_kind = 'system' and answered_by_id is null)
);

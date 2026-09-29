-- Who wrote a checklist answer: a person, or Vectispire itself — decision 0032, amendment "the scans
-- answer the lines they measure" (2026-09-29).
--
-- Written three times, not in common: an answer by Vectispire belongs to no account, so
-- `answered_by_id` stops being `not null`, and SQLite cannot change a column's nullability: the table
-- is rebuilt — created anew, its rows copied with their ids, the old one dropped, the new one renamed
-- and its index made again. No foreign key names it (decision 0032 §1), so nothing else moves.
--
-- `answered_by_kind` is the distinction, and it is structural on purpose: `answered_by` is a name, and
-- an account may be called "Vectispire" — usernames are free text. `person` for every row written
-- before, and for every answer a person gives; `system` for one Vectispire wrote from a measurement,
-- which names no account. The check keeps the two apart: a person's answer names its account, the
-- system's names none, and a system row can never pass for a person's by carrying an id.
--
-- `withdrawn` marks the row by which Vectispire withdraws its own answer when the measurement it
-- rested on no longer has data: the table stays append-only, the line's current answer becomes none,
-- and the history keeps both. Only the system withdraws, which the check states too.
create table t_checklist_answer_v56 (
    id integer primary key autoincrement,
    checklist_id bigint not null,
    item_id bigint not null,
    answer_value varchar(20) not null,
    answer_comment text,
    answered_by varchar(255) not null,
    answered_by_id bigint,
    answered_at numeric not null,
    measurement_id bigint,
    carried_from_id bigint,
    carried_by varchar(255),
    carried_by_id bigint,
    carried_at numeric,
    needs_confirmation boolean not null default 0,
    edition int not null,
    answered_by_kind varchar(10) not null default 'person',
    withdrawn boolean not null default 0,
    constraint ck_checklist_answer_author check (
        (answered_by_kind = 'person' and answered_by_id is not null and withdrawn = 0)
        or (answered_by_kind = 'system' and answered_by_id is null)
    )
);

insert into t_checklist_answer_v56 (id, checklist_id, item_id, answer_value, answer_comment, answered_by,
        answered_by_id, answered_at, measurement_id, carried_from_id, carried_by, carried_by_id, carried_at,
        needs_confirmation, edition, answered_by_kind, withdrawn)
    select id, checklist_id, item_id, answer_value, answer_comment, answered_by, answered_by_id, answered_at,
        measurement_id, carried_from_id, carried_by, carried_by_id, carried_at, needs_confirmation, edition,
        'person', 0
    from t_checklist_answer;

drop table t_checklist_answer;

alter table t_checklist_answer_v56 rename to t_checklist_answer;

create index idx_checklist_answer_line on t_checklist_answer (checklist_id, item_id);

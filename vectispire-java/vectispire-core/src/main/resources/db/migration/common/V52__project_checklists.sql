-- Project checklists, answered by people — decision 0032 §1, §4 and §5.
--
-- Written once, in common: four new tables and no foreign key. Every row names a project, and the
-- `checklists` module's listener purges them in the transaction that deletes it (`ProjectDeleted`,
-- open question 10), as the plugin activations are; a key would have to be written three times.

-- One revision of a project's answers against one template version. `revision` numbers a project's
-- checklists 1, 2, 3… and is what the routes name; `edition` counts the writes to this revision — an
-- answer, a proof, a submission — and every write names the edition its writer read, so that one
-- person's work is never silently replaced by another's. `supersedes_id` is the revision this one
-- was opened from, by a move to another version or by a reopening.
--
-- **At most one open checklist per project** is the key on `(project_id, open_slot)`: `open_slot` is
-- 1 while the revision is a draft or submitted and null once it is signed off or superseded, and all
-- three engines let a unique key hold several nulls — which a partial index would have needed three
-- dialects to say. Two people opening a project's checklist at once: one insert fails.
--
-- `sign_off_four_eyes` records whether the rule required the signer to differ from the revision's
-- authors when it was signed off — the document states which rule applied — and is null until then.
create table t_checklist (
    id ${id},
    project_id bigint not null,
    template_version_id bigint not null,
    revision int not null,
    status varchar(20) not null,
    edition int not null,
    open_slot int,
    author_id bigint not null,
    author varchar(255) not null,
    opened_at ${ts} not null,
    opened_by varchar(255) not null,
    supersedes_id bigint,
    submitted_at ${ts},
    submitted_by varchar(255),
    submitted_by_id bigint,
    returned_at ${ts},
    returned_by varchar(255),
    return_reason ${text},
    signed_off_at ${ts},
    signed_off_by varchar(255),
    signed_off_by_id bigint,
    sign_off_four_eyes ${bool},
    superseded_at ${ts},
    superseded_by varchar(255),
    constraint uq_checklist_revision unique (project_id, revision),
    constraint uq_checklist_open_slot unique (project_id, open_slot)
);

-- One answer to one line, **never updated**: answering again is a new row, and the current answer is
-- the newest row per item. `answered_by` and `answered_at` are the person who gave it and when — kept
-- by a carried copy, which names who carried it, and when, beside them (§4). `needs_confirmation`
-- marks a copy carried onto a line whose wording, KPI, evidence or binding changed: the revision is
-- not submitted until somebody answers or confirms it. `edition` is the revision's edition the row
-- was written at, what a later write on the same line compares with. `measurement_id` is a later
-- lot's (§6) and null until then. The comment is bounded before the write, at 4,000 characters.
create table t_checklist_answer (
    id ${id},
    checklist_id bigint not null,
    item_id bigint not null,
    answer_value varchar(20) not null,
    answer_comment ${text},
    answered_by varchar(255) not null,
    answered_by_id bigint not null,
    answered_at ${ts} not null,
    measurement_id bigint,
    carried_from_id bigint,
    carried_by varchar(255),
    carried_by_id bigint,
    carried_at ${ts},
    needs_confirmation ${bool} not null default ${false},
    edition int not null
);

create index idx_checklist_answer_line on t_checklist_answer (checklist_id, item_id);

-- A proof attached to a line: a link, or a file whose bytes are in t_checklist_file. Withdrawn, never
-- deleted, while the revision is a draft, and the withdrawal is dated and attributed. `performed_on`
-- is the day the work was done, and `valid_until` the day it stops holding, for a line that says
-- how long a proof holds. A proof carried into the next revision is a new row naming the one it came
-- from, and its file is the same file.
create table t_checklist_evidence (
    id ${id},
    checklist_id bigint not null,
    item_id bigint not null,
    kind varchar(10) not null,
    link varchar(2000),
    file_id bigint,
    file_name varchar(255),
    media_type varchar(255),
    file_size bigint,
    file_sha256 varchar(64),
    performed_on ${ts} not null,
    valid_until ${ts},
    added_by varchar(255) not null,
    added_by_id bigint not null,
    added_at ${ts} not null,
    carried_from_id bigint,
    carried_by_id bigint,
    edition int not null,
    withdrawn_by varchar(255),
    withdrawn_by_id bigint,
    withdrawn_at ${ts},
    withdrawn_edition int
);

create index idx_checklist_evidence_line on t_checklist_evidence (checklist_id, item_id);

-- The bytes of an uploaded proof, apart, so that no listing ever loads them (§1): at most the route's
-- ceiling, 25 MB. `project_id` is what the purge finds them by, since several revisions' proofs may
-- share one file.
create table t_checklist_file (
    id ${id},
    project_id bigint not null,
    sha256 varchar(64) not null,
    size_bytes bigint not null,
    content ${bytes} not null
);

create index idx_checklist_file_project on t_checklist_file (project_id);

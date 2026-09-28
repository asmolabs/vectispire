-- Checklist templates, their versions and their items — decision 0032 §1, §3 and §4.
--
-- Written once, in common: three new tables, no foreign key. Nothing but the `checklists` module
-- names these rows, and a template is the organisation's, not a target's, so no other module's
-- deletion ever reaches them; a key would have to be written three times for no purge.

-- The organisation's checklist, under a slug that is never reused: a project's checklist names its
-- template's versions, and another template under the same slug would inherit them.
create table t_checklist_template (
    id ${id},
    slug varchar(64) not null,
    name varchar(200) not null,
    created_at ${ts} not null,
    created_by varchar(255) not null,
    constraint uq_checklist_template_slug unique (slug)
);

-- One version of a template: the workbook it came from, kept whole, where its checklist lives in
-- that workbook, and who moved it through draft, published and retired.
--
-- `source_bytes` is the file as received — at most the import route's ceiling, 10 MB — and the
-- renderer writes into it; `source_sha256` is what a delivered document is compared with.
-- `layout` stays null until a person has confirmed one: the reader only proposes (§3, step 1), and
-- a draft without a confirmed layout has no item and cannot be published. `item_pairs` holds the
-- pairs made by hand with the previous version (§4), and `previous_version_id` which version that
-- is — fixed when the draft is made, so that retiring another version meanwhile cannot change what
-- the draft was paired with. `draft_authors` lists every account that wrote the draft — imported or
-- derived it, confirmed its layout, paired its items — which four-eyes refuses as its publisher.
-- `ordinal` is unique per template, which is also what keeps two drafts made at once from both
-- taking the next number. `revision` counts the draft's edits: every edit and every change of status
-- is a conditional update on the revision its writer read, and publishing names the revision the
-- publisher reviewed — so an edit an author makes after the review is never published unseen.
create table t_checklist_template_version (
    id ${id},
    template_id bigint not null,
    ordinal int not null,
    label varchar(200),
    status varchar(20) not null,
    revision int not null,
    source_sha256 varchar(64) not null,
    source_size bigint not null,
    source_bytes ${bytes} not null,
    layout ${text},
    offers_not_applicable ${bool} not null default ${false},
    item_pairs ${text},
    previous_version_id bigint,
    derived_from_version_id bigint,
    draft_authors ${text} not null,
    imported_at ${ts} not null,
    imported_by varchar(255) not null,
    published_at ${ts},
    published_by varchar(255),
    retired_at ${ts},
    retired_by varchar(255),
    constraint uq_checklist_template_version_ordinal unique (template_id, ordinal)
);

create index idx_checklist_template_version_status on t_checklist_template_version (template_id, status);

-- One line of a version, in the template's words as imported. `item_key` follows the line across
-- versions and `content_digest` says whether what it asks changed (§4); the control and the KPI
-- are long text, the rest bounded as `ChecklistItem` bounds them. `bound_rule` is a later lot's
-- (§6) and null until a rule is bound.
create table t_checklist_item (
    id ${id},
    version_id bigint not null,
    item_key varchar(255) not null,
    item_position int not null,
    domain varchar(1000) not null,
    objective varchar(1000) not null,
    control ${text} not null,
    contact varchar(255) not null,
    kpi ${text} not null,
    content_digest varchar(64) not null,
    sheet_row int not null,
    evidence_kind varchar(20) not null,
    evidence_validity_months int,
    bound_rule ${text},
    constraint uq_checklist_item_key unique (version_id, item_key)
);

create index idx_checklist_item_position on t_checklist_item (version_id, item_position);

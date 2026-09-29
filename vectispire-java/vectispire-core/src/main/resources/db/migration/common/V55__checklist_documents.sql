-- A signed-off revision's document — decision 0032 §1 and §10.
--
-- Written once, in common: one new table, no foreign key. Every row names a checklist and its project,
-- and the `checklists` module's listener purges them with the project's checklists (`ProjectDeleted`,
-- open question 10), as it purges the proofs' files.
--
-- The package is rendered and signed **inside the sign-off's transaction** and stored here, so that the
-- document an auditor receives next year is the one that was signed, not a rendering of rows read again.
-- `content` is the zip exactly as the route serves it — `checklist.xlsx`, `checklist.json` and their
-- detached signatures — and `sha256` its digest; the two parts' digests and signatures are kept beside it,
-- with the key that made them, so that a document can be checked without unpacking it. `product_version`
-- is the Vectispire version that produced it, null when the build states none.
--
-- At most one per revision: the key on `checklist_id` refuses a second, and is the index the route reads.
create table t_checklist_document (
    id ${id},
    checklist_id bigint not null,
    project_id bigint not null,
    content ${bytes} not null,
    size_bytes bigint not null,
    sha256 varchar(64) not null,
    workbook_sha256 varchar(64) not null,
    workbook_signature varchar(255) not null,
    statement_sha256 varchar(64) not null,
    statement_signature varchar(255) not null,
    signing_key_id varchar(128) not null,
    product_version varchar(100),
    produced_at ${ts} not null,
    constraint uq_checklist_document unique (checklist_id)
);

create index idx_checklist_document_project on t_checklist_document (project_id);

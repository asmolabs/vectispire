//! `t_checklist`, `t_checklist_answer`, `t_checklist_evidence`, `t_checklist_file` (V52, V56),
//! `t_checklist_measurement` (V54) and `t_checklist_document` (V55).

use vectispire_cp_db::Tx;
use vectispire_cp_db::types::UtcInstant;

use super::{StoreError, engines};

/// A row of `t_checklist`: one revision of a project's checklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChecklistRow {
    pub id: i64,
    pub project_id: i64,
    pub template_version_id: i64,
    pub revision: i32,
    pub status: String,
    pub edition: i32,
    pub open_slot: Option<i32>,
    pub author_id: i64,
    pub author: String,
    pub opened_at: UtcInstant,
    pub opened_by: String,
    pub supersedes_id: Option<i64>,
    pub submitted_at: Option<UtcInstant>,
    pub submitted_by: Option<String>,
    pub submitted_by_id: Option<i64>,
    pub returned_at: Option<UtcInstant>,
    pub returned_by: Option<String>,
    pub return_reason: Option<String>,
    pub signed_off_at: Option<UtcInstant>,
    pub signed_off_by: Option<String>,
    pub signed_off_by_id: Option<i64>,
    pub sign_off_four_eyes: Option<bool>,
    pub superseded_at: Option<UtcInstant>,
    pub superseded_by: Option<String>,
}

/// A row of `t_checklist_answer`. `answered_by_id` is null for Vectispire's own (V56).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnswerRow {
    pub id: i64,
    pub checklist_id: i64,
    pub item_id: i64,
    pub value: String,
    pub comment: Option<String>,
    pub answered_by: String,
    pub answered_by_id: Option<i64>,
    pub answered_by_kind: String,
    pub answered_at: UtcInstant,
    pub measurement_id: Option<i64>,
    pub carried_from_id: Option<i64>,
    pub carried_by: Option<String>,
    pub carried_by_id: Option<i64>,
    pub carried_at: Option<UtcInstant>,
    pub needs_confirmation: bool,
    pub withdrawn: bool,
    pub edition: i32,
}

/// A row of `t_checklist_evidence`: a link or a file proving a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvidenceRow {
    pub id: i64,
    pub checklist_id: i64,
    pub item_id: i64,
    pub kind: String,
    pub link: Option<String>,
    pub file_id: Option<i64>,
    pub file_name: Option<String>,
    pub media_type: Option<String>,
    pub file_size: Option<i64>,
    pub file_sha256: Option<String>,
    pub performed_on: UtcInstant,
    pub valid_until: Option<UtcInstant>,
    pub added_by: String,
    pub added_by_id: i64,
    pub added_at: UtcInstant,
    pub carried_from_id: Option<i64>,
    pub carried_by_id: Option<i64>,
    pub edition: i32,
    pub withdrawn_by: Option<String>,
    pub withdrawn_by_id: Option<i64>,
    pub withdrawn_at: Option<UtcInstant>,
    pub withdrawn_edition: Option<i32>,
}

/// A row of `t_checklist_measurement`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MeasurementRow {
    pub id: i64,
    pub checklist_id: i64,
    pub item_id: i64,
    pub purpose: String,
    pub rule_kind: String,
    pub rule_digest: String,
    pub bound_rule: String,
    pub outcome: String,
    pub reason: Option<String>,
    pub as_of: Option<UtcInstant>,
    pub computed_at: UtcInstant,
    pub computed_by: String,
    pub answer_id: Option<i64>,
    pub answer_value: Option<String>,
    pub reconciliation: Option<String>,
    pub evidence_digest: String,
    pub evidence: String,
}

/// A row of `t_checklist_document`: a signed-off revision's package as signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DocumentRow {
    pub id: i64,
    pub checklist_id: i64,
    pub project_id: i64,
    pub content: Vec<u8>,
    pub size_bytes: i64,
    pub sha256: String,
    pub workbook_sha256: String,
    pub workbook_signature: String,
    pub statement_sha256: String,
    pub statement_signature: String,
    pub signing_key_id: String,
    pub product_version: Option<String>,
    pub produced_at: UtcInstant,
}

// ------------------------------------------------------------------ checklists

macro_rules! checklist_columns {
    ($kind:ident!($row:ident, $head:tt, $tail:tt $(, $arg:expr)* $(,)?)) => {
        sqlx::$kind!($row, $head + r#"id, project_id, template_version_id, revision, status, edition, open_slot, author_id, author,
           opened_at as "opened_at: UtcInstant", opened_by, supersedes_id, submitted_at as "submitted_at: UtcInstant",
           submitted_by, submitted_by_id, returned_at as "returned_at: UtcInstant", returned_by, return_reason,
           signed_off_at as "signed_off_at: UtcInstant", signed_off_by, signed_off_by_id,
           sign_off_four_eyes as "sign_off_four_eyes: bool", superseded_at as "superseded_at: UtcInstant",
           superseded_by"# + $tail $(, $arg)*)
    };
}

pub(crate) async fn checklist_by_id(tx: &mut Tx, id: i64) -> Result<Option<ChecklistRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(checklist_columns!(query_as!(
            ChecklistRow,
            "/* mysql */ select ",
            " from t_checklist where id = ?",
            id
        ))
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(checklist_columns!(query_as!(
            ChecklistRow,
            "/* postgres */ select ",
            " from t_checklist where id = $1",
            id
        ))
        .fetch_optional(&mut **tx)
        .await?),
    )
}

/// `findByProjectIdOrderByRevisionDesc`.
pub(crate) async fn checklists_of_project(tx: &mut Tx, project_id: i64) -> Result<Vec<ChecklistRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(checklist_columns!(query_as!(
            ChecklistRow,
            "/* mysql */ select ",
            " from t_checklist where project_id = ? order by revision desc",
            project_id
        ))
        .fetch_all(&mut **tx)
        .await?),
        |tx| Ok(checklist_columns!(query_as!(
            ChecklistRow,
            "/* postgres */ select ",
            " from t_checklist where project_id = $1 order by revision desc",
            project_id
        ))
        .fetch_all(&mut **tx)
        .await?),
    )
}

/// `findFirstByProjectIdOrderByRevisionDesc`.
pub(crate) async fn latest_checklist(tx: &mut Tx, project_id: i64) -> Result<Option<ChecklistRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(checklist_columns!(query_as!(
            ChecklistRow,
            "/* mysql */ select ",
            " from t_checklist where project_id = ? order by revision desc limit 1",
            project_id
        ))
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(checklist_columns!(query_as!(
            ChecklistRow,
            "/* postgres */ select ",
            " from t_checklist where project_id = $1 order by revision desc limit 1",
            project_id
        ))
        .fetch_optional(&mut **tx)
        .await?),
    )
}

/// `findByProjectIdAndRevision`.
pub(crate) async fn checklist_revision(
    tx: &mut Tx,
    project_id: i64,
    revision: i32,
) -> Result<Option<ChecklistRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(checklist_columns!(query_as!(
            ChecklistRow,
            "/* mysql */ select ",
            " from t_checklist where project_id = ? and revision = ?",
            project_id,
            revision
        ))
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(checklist_columns!(query_as!(
            ChecklistRow,
            "/* postgres */ select ",
            " from t_checklist where project_id = $1 and revision = $2",
            project_id,
            revision
        ))
        .fetch_optional(&mut **tx)
        .await?),
    )
}

/// `findByStatusOrderByProjectIdAsc`.
pub(crate) async fn checklists_in(tx: &mut Tx, status: &str) -> Result<Vec<ChecklistRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(checklist_columns!(query_as!(
            ChecklistRow,
            "/* mysql */ select ",
            " from t_checklist where status = ? order by project_id asc",
            status
        ))
        .fetch_all(&mut **tx)
        .await?),
        |tx| Ok(checklist_columns!(query_as!(
            ChecklistRow,
            "/* postgres */ select ",
            " from t_checklist where status = $1 order by project_id asc",
            status
        ))
        .fetch_all(&mut **tx)
        .await?),
    )
}

/// A revision's first row: a draft at edition 1, holding the project's open slot.
#[derive(Debug, Clone)]
pub(crate) struct NewChecklist<'a> {
    pub project_id: i64,
    pub template_version_id: i64,
    pub revision: i32,
    pub status: &'a str,
    pub author_id: i64,
    pub author: &'a str,
    pub opened_at: UtcInstant,
    pub supersedes_id: Option<i64>,
}

pub(crate) async fn insert_checklist(tx: &mut Tx, row: &NewChecklist<'_>) -> Result<i64, StoreError> {
    let c = row;
    engines!(
        tx,
        |tx| {
            let done = sqlx::query!(
                "/* mysql */ insert into t_checklist (project_id, template_version_id, revision, status, edition, \
                 open_slot, author_id, author, opened_at, opened_by, supersedes_id) values (?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?)",
                c.project_id,
                c.template_version_id,
                c.revision,
                c.status,
                c.author_id,
                c.author,
                c.opened_at,
                c.author,
                c.supersedes_id
            )
            .execute(&mut **tx)
            .await?;
            super::inserted(&done)
        },
        |tx| Ok(sqlx::query_scalar!(
            "/* postgres */ insert into t_checklist (project_id, template_version_id, revision, status, edition, \
             open_slot, author_id, author, opened_at, opened_by, supersedes_id) \
             values ($1, $2, $3, $4, 1, 1, $5, $6, $7, $6, $8) returning id",
            c.project_id,
            c.template_version_id,
            c.revision,
            c.status,
            c.author_id,
            c.author,
            c.opened_at as UtcInstant,
            c.supersedes_id
        )
        .fetch_one(&mut **tx)
        .await?),
    )
}

/// `touchDraft`: the edition moved on, if the draft is still at the one read.
pub(crate) async fn touch_draft(tx: &mut Tx, id: i64, edition: i32, draft: &str) -> Result<u64, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query!(
            "/* mysql */ update t_checklist set edition = edition + 1 where id = ? and edition = ? and status = ?",
            id,
            edition,
            draft
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
        |tx| {
            Ok(sqlx::query!(
            "/* postgres */ update t_checklist set edition = edition + 1 where id = $1 and edition = $2 and status = $3",
            id,
            edition,
            draft
        )
        .execute(&mut **tx)
        .await?
        .rows_affected())
        },
    )
}

/// `submit`.
#[allow(clippy::too_many_arguments)] // the update's columns, each a parameter as Java's `@Param`s are
pub(crate) async fn submit_checklist(
    tx: &mut Tx,
    id: i64,
    edition: i32,
    draft: &str,
    submitted: &str,
    at: UtcInstant,
    by: &str,
    by_id: i64,
) -> Result<u64, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query!(
            "/* mysql */ update t_checklist set status = ?, edition = edition + 1, submitted_at = ?, submitted_by = ?, \
             submitted_by_id = ? where id = ? and edition = ? and status = ?",
            submitted,
            at,
            by,
            by_id,
            id,
            edition,
            draft
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
        |tx| Ok(sqlx::query!(
            "/* postgres */ update t_checklist set status = $1, edition = edition + 1, submitted_at = $2, \
             submitted_by = $3, submitted_by_id = $4 where id = $5 and edition = $6 and status = $7",
            submitted,
            at as UtcInstant,
            by,
            by_id,
            id,
            edition,
            draft
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
    )
}

/// `returnToDraft`.
#[allow(clippy::too_many_arguments)] // the update's columns, each a parameter as Java's `@Param`s are
pub(crate) async fn return_checklist(
    tx: &mut Tx,
    id: i64,
    edition: i32,
    submitted: &str,
    draft: &str,
    at: UtcInstant,
    by: &str,
    reason: &str,
) -> Result<u64, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query!(
            "/* mysql */ update t_checklist set status = ?, edition = edition + 1, returned_at = ?, returned_by = ?, \
             return_reason = ? where id = ? and edition = ? and status = ?",
            draft,
            at,
            by,
            reason,
            id,
            edition,
            submitted
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
        |tx| Ok(sqlx::query!(
            "/* postgres */ update t_checklist set status = $1, edition = edition + 1, returned_at = $2, \
             returned_by = $3, return_reason = $4 where id = $5 and edition = $6 and status = $7",
            draft,
            at as UtcInstant,
            by,
            reason,
            id,
            edition,
            submitted
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
    )
}

/// `signOff`: the open slot freed.
#[allow(clippy::too_many_arguments)] // the update's columns, each a parameter as Java's `@Param`s are
pub(crate) async fn sign_off_checklist(
    tx: &mut Tx,
    id: i64,
    edition: i32,
    submitted: &str,
    signed_off: &str,
    at: UtcInstant,
    by: &str,
    by_id: i64,
    four_eyes: bool,
) -> Result<u64, StoreError> {
    engines!(
        tx,
        |tx| {
            Ok(sqlx::query!(
            "/* mysql */ update t_checklist set status = ?, edition = edition + 1, open_slot = null, signed_off_at = ?, \
             signed_off_by = ?, signed_off_by_id = ?, sign_off_four_eyes = ? where id = ? and edition = ? and status = ?",
            signed_off,
            at,
            by,
            by_id,
            four_eyes,
            id,
            edition,
            submitted
        )
        .execute(&mut **tx)
        .await?
        .rows_affected())
        },
        |tx| Ok(sqlx::query!(
            "/* postgres */ update t_checklist set status = $1, edition = edition + 1, open_slot = null, \
             signed_off_at = $2, signed_off_by = $3, signed_off_by_id = $4, sign_off_four_eyes = $5 \
             where id = $6 and edition = $7 and status = $8",
            signed_off,
            at as UtcInstant,
            by,
            by_id,
            four_eyes,
            id,
            edition,
            submitted
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
    )
}

/// `supersede`: an open revision — a draft or a submitted one — set aside by the next, its slot freed.
pub(crate) async fn supersede_checklist(
    tx: &mut Tx,
    id: i64,
    edition: i32,
    superseded: &str,
    at: UtcInstant,
    by: &str,
) -> Result<u64, StoreError> {
    // `ChecklistStatus.OPEN`, the statuses that hold the project's one open slot, written out: the list is fixed.
    engines!(
        tx,
        |tx| {
            Ok(sqlx::query!(
            "/* mysql */ update t_checklist set status = ?, edition = edition + 1, open_slot = null, superseded_at = ?, \
             superseded_by = ? where id = ? and edition = ? and status in ('draft', 'submitted')",
            superseded,
            at,
            by,
            id,
            edition
        )
        .execute(&mut **tx)
        .await?
        .rows_affected())
        },
        |tx| {
            Ok(sqlx::query!(
            "/* postgres */ update t_checklist set status = $1, edition = edition + 1, open_slot = null, \
             superseded_at = $2, superseded_by = $3 where id = $4 and edition = $5 and status in ('draft', 'submitted')",
            superseded,
            at as UtcInstant,
            by,
            id,
            edition
        )
        .execute(&mut **tx)
        .await?
        .rows_affected())
        },
    )
}

pub(crate) async fn delete_checklists_of_project(tx: &mut Tx, project_id: i64) -> Result<(), StoreError> {
    engines!(
        tx,
        |tx| {
            sqlx::query!("/* mysql */ delete from t_checklist where project_id = ?", project_id)
                .execute(&mut **tx)
                .await?;
            Ok(())
        },
        |tx| {
            sqlx::query!("/* postgres */ delete from t_checklist where project_id = $1", project_id)
                .execute(&mut **tx)
                .await?;
            Ok(())
        },
    )
}

// ------------------------------------------------------------------ answers

macro_rules! answer_columns {
    ($kind:ident!($row:ident, $head:tt, $tail:tt $(, $arg:expr)* $(,)?)) => {
        sqlx::$kind!($row, $head + r#"id, checklist_id, item_id, answer_value as value, answer_comment as comment, answered_by, answered_by_id,
           answered_by_kind, answered_at as "answered_at: UtcInstant", measurement_id, carried_from_id, carried_by,
           carried_by_id, carried_at as "carried_at: UtcInstant", needs_confirmation as "needs_confirmation: bool",
           withdrawn as "withdrawn: bool", edition"# + $tail $(, $arg)*)
    };
}

/// `findByChecklistIdOrderByIdAsc`.
pub(crate) async fn answers_of(tx: &mut Tx, checklist_id: i64) -> Result<Vec<AnswerRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(answer_columns!(query_as!(
            AnswerRow,
            "/* mysql */ select ",
            " from t_checklist_answer where checklist_id = ? order by id asc",
            checklist_id
        ))
        .fetch_all(&mut **tx)
        .await?),
        |tx| Ok(answer_columns!(query_as!(
            AnswerRow,
            "/* postgres */ select ",
            " from t_checklist_answer where checklist_id = $1 order by id asc",
            checklist_id
        ))
        .fetch_all(&mut **tx)
        .await?),
    )
}

/// `findByChecklistIdAndItemIdOrderByIdAsc`.
pub(crate) async fn answers_of_line(
    tx: &mut Tx,
    checklist_id: i64,
    item_id: i64,
) -> Result<Vec<AnswerRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(answer_columns!(query_as!(
            AnswerRow,
            "/* mysql */ select ",
            " from t_checklist_answer where checklist_id = ? and item_id = ? order by id asc",
            checklist_id,
            item_id
        ))
        .fetch_all(&mut **tx)
        .await?),
        |tx| Ok(answer_columns!(query_as!(
            AnswerRow,
            "/* postgres */ select ",
            " from t_checklist_answer where checklist_id = $1 and item_id = $2 order by id asc",
            checklist_id,
            item_id
        ))
        .fetch_all(&mut **tx)
        .await?),
    )
}

/// An answer's row before its identity; `id` is ignored.
pub(crate) async fn insert_answer(tx: &mut Tx, answer: &AnswerRow) -> Result<i64, StoreError> {
    let a = answer;
    engines!(
        tx,
        |tx| {
            let done = sqlx::query!(
                "/* mysql */ insert into t_checklist_answer (checklist_id, item_id, answer_value, answer_comment, \
                 answered_by, answered_by_id, answered_by_kind, answered_at, measurement_id, carried_from_id, carried_by, \
                 carried_by_id, carried_at, needs_confirmation, withdrawn, edition) \
                 values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                a.checklist_id,
                a.item_id,
                a.value,
                a.comment,
                a.answered_by,
                a.answered_by_id,
                a.answered_by_kind,
                a.answered_at,
                a.measurement_id,
                a.carried_from_id,
                a.carried_by,
                a.carried_by_id,
                a.carried_at,
                a.needs_confirmation,
                a.withdrawn,
                a.edition
            )
            .execute(&mut **tx)
            .await?;
            super::inserted(&done)
        },
        |tx| Ok(sqlx::query_scalar!(
            "/* postgres */ insert into t_checklist_answer (checklist_id, item_id, answer_value, answer_comment, \
             answered_by, answered_by_id, answered_by_kind, answered_at, measurement_id, carried_from_id, carried_by, \
             carried_by_id, carried_at, needs_confirmation, withdrawn, edition) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) returning id",
            a.checklist_id,
            a.item_id,
            a.value,
            a.comment,
            a.answered_by,
            a.answered_by_id,
            a.answered_by_kind,
            a.answered_at as UtcInstant,
            a.measurement_id,
            a.carried_from_id,
            a.carried_by,
            a.carried_by_id,
            a.carried_at as Option<UtcInstant>,
            a.needs_confirmation,
            a.withdrawn,
            a.edition
        )
        .fetch_one(&mut **tx)
        .await?),
    )
}

pub(crate) async fn delete_answers_of_project(tx: &mut Tx, project_id: i64) -> Result<(), StoreError> {
    engines!(
        tx,
        |tx| {
            sqlx::query!(
                "/* mysql */ delete from t_checklist_answer where checklist_id in \
                 (select c.id from t_checklist c where c.project_id = ?)",
                project_id
            )
            .execute(&mut **tx)
            .await?;
            Ok(())
        },
        |tx| {
            sqlx::query!(
                "/* postgres */ delete from t_checklist_answer where checklist_id in \
                 (select c.id from t_checklist c where c.project_id = $1)",
                project_id
            )
            .execute(&mut **tx)
            .await?;
            Ok(())
        },
    )
}

// ------------------------------------------------------------------ evidence and files

macro_rules! evidence_columns {
    ($kind:ident!($row:ident, $head:tt, $tail:tt $(, $arg:expr)* $(,)?)) => {
        sqlx::$kind!($row, $head + r#"id, checklist_id, item_id, kind, link, file_id, file_name, media_type, file_size, file_sha256,
           performed_on as "performed_on: UtcInstant", valid_until as "valid_until: UtcInstant", added_by, added_by_id,
           added_at as "added_at: UtcInstant", carried_from_id, carried_by_id, edition, withdrawn_by, withdrawn_by_id,
           withdrawn_at as "withdrawn_at: UtcInstant", withdrawn_edition"# + $tail $(, $arg)*)
    };
}

/// `findByChecklistIdOrderByIdAsc`.
pub(crate) async fn evidence_of(tx: &mut Tx, checklist_id: i64) -> Result<Vec<EvidenceRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(evidence_columns!(query_as!(
            EvidenceRow,
            "/* mysql */ select ",
            " from t_checklist_evidence where checklist_id = ? order by id asc",
            checklist_id
        ))
        .fetch_all(&mut **tx)
        .await?),
        |tx| Ok(evidence_columns!(query_as!(
            EvidenceRow,
            "/* postgres */ select ",
            " from t_checklist_evidence where checklist_id = $1 order by id asc",
            checklist_id
        ))
        .fetch_all(&mut **tx)
        .await?),
    )
}

/// `findByChecklistIdAndItemIdOrderByIdAsc`.
pub(crate) async fn evidence_of_line(
    tx: &mut Tx,
    checklist_id: i64,
    item_id: i64,
) -> Result<Vec<EvidenceRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(evidence_columns!(query_as!(
            EvidenceRow,
            "/* mysql */ select ",
            " from t_checklist_evidence where checklist_id = ? and item_id = ? order by id asc",
            checklist_id,
            item_id
        ))
        .fetch_all(&mut **tx)
        .await?),
        |tx| Ok(evidence_columns!(query_as!(
            EvidenceRow,
            "/* postgres */ select ",
            " from t_checklist_evidence where checklist_id = $1 and item_id = $2 order by id asc",
            checklist_id,
            item_id
        ))
        .fetch_all(&mut **tx)
        .await?),
    )
}

pub(crate) async fn evidence_by_id(tx: &mut Tx, id: i64) -> Result<Option<EvidenceRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(evidence_columns!(query_as!(
            EvidenceRow,
            "/* mysql */ select ",
            " from t_checklist_evidence where id = ?",
            id
        ))
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(evidence_columns!(query_as!(
            EvidenceRow,
            "/* postgres */ select ",
            " from t_checklist_evidence where id = $1",
            id
        ))
        .fetch_optional(&mut **tx)
        .await?),
    )
}

/// A proof's row before its identity; `id` and the withdrawal are ignored.
pub(crate) async fn insert_evidence(tx: &mut Tx, proof: &EvidenceRow) -> Result<i64, StoreError> {
    let e = proof;
    engines!(
        tx,
        |tx| {
            let done = sqlx::query!(
                "/* mysql */ insert into t_checklist_evidence (checklist_id, item_id, kind, link, file_id, file_name, \
                 media_type, file_size, file_sha256, performed_on, valid_until, added_by, added_by_id, added_at, \
                 carried_from_id, carried_by_id, edition) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                e.checklist_id,
                e.item_id,
                e.kind,
                e.link,
                e.file_id,
                e.file_name,
                e.media_type,
                e.file_size,
                e.file_sha256,
                e.performed_on,
                e.valid_until,
                e.added_by,
                e.added_by_id,
                e.added_at,
                e.carried_from_id,
                e.carried_by_id,
                e.edition
            )
            .execute(&mut **tx)
            .await?;
            super::inserted(&done)
        },
        |tx| Ok(sqlx::query_scalar!(
            "/* postgres */ insert into t_checklist_evidence (checklist_id, item_id, kind, link, file_id, file_name, \
             media_type, file_size, file_sha256, performed_on, valid_until, added_by, added_by_id, added_at, \
             carried_from_id, carried_by_id, edition) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) returning id",
            e.checklist_id,
            e.item_id,
            e.kind,
            e.link,
            e.file_id,
            e.file_name,
            e.media_type,
            e.file_size,
            e.file_sha256,
            e.performed_on as UtcInstant,
            e.valid_until as Option<UtcInstant>,
            e.added_by,
            e.added_by_id,
            e.added_at as UtcInstant,
            e.carried_from_id,
            e.carried_by_id,
            e.edition
        )
        .fetch_one(&mut **tx)
        .await?),
    )
}

/// `withdraw`: once.
pub(crate) async fn withdraw_evidence(
    tx: &mut Tx,
    id: i64,
    at: UtcInstant,
    by: &str,
    by_id: i64,
    edition: i32,
) -> Result<u64, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query!(
            "/* mysql */ update t_checklist_evidence set withdrawn_at = ?, withdrawn_by = ?, withdrawn_by_id = ?, \
             withdrawn_edition = ? where id = ? and withdrawn_at is null",
            at,
            by,
            by_id,
            edition,
            id
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
        |tx| {
            Ok(sqlx::query!(
            "/* postgres */ update t_checklist_evidence set withdrawn_at = $1, withdrawn_by = $2, withdrawn_by_id = $3, \
             withdrawn_edition = $4 where id = $5 and withdrawn_at is null",
            at as UtcInstant,
            by,
            by_id,
            edition,
            id
        )
        .execute(&mut **tx)
        .await?
        .rows_affected())
        },
    )
}

pub(crate) async fn delete_evidence_of_project(tx: &mut Tx, project_id: i64) -> Result<(), StoreError> {
    engines!(
        tx,
        |tx| {
            sqlx::query!(
                "/* mysql */ delete from t_checklist_evidence where checklist_id in \
                 (select c.id from t_checklist c where c.project_id = ?)",
                project_id
            )
            .execute(&mut **tx)
            .await?;
            Ok(())
        },
        |tx| {
            sqlx::query!(
                "/* postgres */ delete from t_checklist_evidence where checklist_id in \
                 (select c.id from t_checklist c where c.project_id = $1)",
                project_id
            )
            .execute(&mut **tx)
            .await?;
            Ok(())
        },
    )
}

pub(crate) async fn insert_file(tx: &mut Tx, project_id: i64, sha256: &str, content: &[u8]) -> Result<i64, StoreError> {
    let size = i64::try_from(content.len()).unwrap_or(i64::MAX);
    engines!(
        tx,
        |tx| {
            let done = sqlx::query!(
                "/* mysql */ insert into t_checklist_file (project_id, sha256, size_bytes, content) values (?, ?, ?, ?)",
                project_id,
                sha256,
                size,
                content
            )
            .execute(&mut **tx)
            .await?;
            super::inserted(&done)
        },
        |tx| Ok(sqlx::query_scalar!(
            "/* postgres */ insert into t_checklist_file (project_id, sha256, size_bytes, content) \
             values ($1, $2, $3, $4) returning id",
            project_id,
            sha256,
            size,
            content
        )
        .fetch_one(&mut **tx)
        .await?),
    )
}

/// A stored file's bytes.
pub(crate) async fn file_content(tx: &mut Tx, id: i64) -> Result<Option<Vec<u8>>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_scalar!("/* mysql */ select content from t_checklist_file where id = ?", id)
            .fetch_optional(&mut **tx)
            .await?),
        |tx| Ok(sqlx::query_scalar!("/* postgres */ select content from t_checklist_file where id = $1", id)
            .fetch_optional(&mut **tx)
            .await?),
    )
}

pub(crate) async fn delete_files_of_project(tx: &mut Tx, project_id: i64) -> Result<(), StoreError> {
    engines!(
        tx,
        |tx| {
            sqlx::query!("/* mysql */ delete from t_checklist_file where project_id = ?", project_id)
                .execute(&mut **tx)
                .await?;
            Ok(())
        },
        |tx| {
            sqlx::query!("/* postgres */ delete from t_checklist_file where project_id = $1", project_id)
                .execute(&mut **tx)
                .await?;
            Ok(())
        },
    )
}

// ------------------------------------------------------------------ measurements

macro_rules! measurement_columns {
    ($kind:ident!($row:ident, $head:tt, $tail:tt $(, $arg:expr)* $(,)?)) => {
        sqlx::$kind!($row, $head + r#"id, checklist_id, item_id, purpose, rule_kind, rule_digest, bound_rule, outcome, reason,
           as_of as "as_of: UtcInstant", computed_at as "computed_at: UtcInstant", computed_by, answer_id, answer_value,
           reconciliation, evidence_digest, evidence"# + $tail $(, $arg)*)
    };
}

/// `findByChecklistIdAndPurposeOrderByIdAsc`.
pub(crate) async fn measurements_of(
    tx: &mut Tx,
    checklist_id: i64,
    purpose: &str,
) -> Result<Vec<MeasurementRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(measurement_columns!(query_as!(
            MeasurementRow,
            "/* mysql */ select ",
            " from t_checklist_measurement where checklist_id = ? and purpose = ? order by id asc",
            checklist_id,
            purpose
        ))
        .fetch_all(&mut **tx)
        .await?),
        |tx| Ok(measurement_columns!(query_as!(
            MeasurementRow,
            "/* postgres */ select ",
            " from t_checklist_measurement where checklist_id = $1 and purpose = $2 order by id asc",
            checklist_id,
            purpose
        ))
        .fetch_all(&mut **tx)
        .await?),
    )
}

/// A measurement's row before its identity; `id` is ignored.
pub(crate) async fn insert_measurement(tx: &mut Tx, row: &MeasurementRow) -> Result<i64, StoreError> {
    let m = row;
    engines!(
        tx,
        |tx| {
            let done = sqlx::query!(
                "/* mysql */ insert into t_checklist_measurement (checklist_id, item_id, purpose, rule_kind, rule_digest, \
                 bound_rule, outcome, reason, as_of, computed_at, computed_by, answer_id, answer_value, reconciliation, \
                 evidence_digest, evidence) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                m.checklist_id,
                m.item_id,
                m.purpose,
                m.rule_kind,
                m.rule_digest,
                m.bound_rule,
                m.outcome,
                m.reason,
                m.as_of,
                m.computed_at,
                m.computed_by,
                m.answer_id,
                m.answer_value,
                m.reconciliation,
                m.evidence_digest,
                m.evidence
            )
            .execute(&mut **tx)
            .await?;
            super::inserted(&done)
        },
        |tx| {
            Ok(sqlx::query_scalar!(
            "/* postgres */ insert into t_checklist_measurement (checklist_id, item_id, purpose, rule_kind, rule_digest, \
             bound_rule, outcome, reason, as_of, computed_at, computed_by, answer_id, answer_value, reconciliation, \
             evidence_digest, evidence) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) returning id",
            m.checklist_id,
            m.item_id,
            m.purpose,
            m.rule_kind,
            m.rule_digest,
            m.bound_rule,
            m.outcome,
            m.reason,
            m.as_of as Option<UtcInstant>,
            m.computed_at as UtcInstant,
            m.computed_by,
            m.answer_id,
            m.answer_value,
            m.reconciliation,
            m.evidence_digest,
            m.evidence
        )
        .fetch_one(&mut **tx)
        .await?)
        },
    )
}

pub(crate) async fn delete_measurements_of_project(tx: &mut Tx, project_id: i64) -> Result<(), StoreError> {
    engines!(
        tx,
        |tx| {
            sqlx::query!(
                "/* mysql */ delete from t_checklist_measurement where checklist_id in \
                 (select c.id from t_checklist c where c.project_id = ?)",
                project_id
            )
            .execute(&mut **tx)
            .await?;
            Ok(())
        },
        |tx| {
            sqlx::query!(
                "/* postgres */ delete from t_checklist_measurement where checklist_id in \
                 (select c.id from t_checklist c where c.project_id = $1)",
                project_id
            )
            .execute(&mut **tx)
            .await?;
            Ok(())
        },
    )
}

// ------------------------------------------------------------------ documents

macro_rules! document_columns {
    ($kind:ident!($row:ident, $head:tt, $tail:tt $(, $arg:expr)* $(,)?)) => {
        sqlx::$kind!($row, $head + r#"id, checklist_id, project_id, content, size_bytes, sha256, workbook_sha256, workbook_signature,
           statement_sha256, statement_signature, signing_key_id, product_version,
           produced_at as "produced_at: UtcInstant""# + $tail $(, $arg)*)
    };
}

/// `findByChecklistId`.
pub(crate) async fn document_of(tx: &mut Tx, checklist_id: i64) -> Result<Option<DocumentRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(document_columns!(query_as!(
            DocumentRow,
            "/* mysql */ select ",
            " from t_checklist_document where checklist_id = ?",
            checklist_id
        ))
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(document_columns!(query_as!(
            DocumentRow,
            "/* postgres */ select ",
            " from t_checklist_document where checklist_id = $1",
            checklist_id
        ))
        .fetch_optional(&mut **tx)
        .await?),
    )
}

/// A document's row before its identity; `id` is ignored.
pub(crate) async fn insert_document(tx: &mut Tx, row: &DocumentRow) -> Result<i64, StoreError> {
    let d = row;
    engines!(
        tx,
        |tx| {
            let done = sqlx::query!(
                "/* mysql */ insert into t_checklist_document (checklist_id, project_id, content, size_bytes, sha256, \
                 workbook_sha256, workbook_signature, statement_sha256, statement_signature, signing_key_id, \
                 product_version, produced_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                d.checklist_id,
                d.project_id,
                d.content,
                d.size_bytes,
                d.sha256,
                d.workbook_sha256,
                d.workbook_signature,
                d.statement_sha256,
                d.statement_signature,
                d.signing_key_id,
                d.product_version,
                d.produced_at
            )
            .execute(&mut **tx)
            .await?;
            super::inserted(&done)
        },
        |tx| Ok(sqlx::query_scalar!(
            "/* postgres */ insert into t_checklist_document (checklist_id, project_id, content, size_bytes, sha256, \
             workbook_sha256, workbook_signature, statement_sha256, statement_signature, signing_key_id, \
             product_version, produced_at) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) returning id",
            d.checklist_id,
            d.project_id,
            d.content,
            d.size_bytes,
            d.sha256,
            d.workbook_sha256,
            d.workbook_signature,
            d.statement_sha256,
            d.statement_signature,
            d.signing_key_id,
            d.product_version,
            d.produced_at as UtcInstant
        )
        .fetch_one(&mut **tx)
        .await?),
    )
}

pub(crate) async fn delete_documents_of_project(tx: &mut Tx, project_id: i64) -> Result<(), StoreError> {
    engines!(
        tx,
        |tx| {
            sqlx::query!("/* mysql */ delete from t_checklist_document where project_id = ?", project_id)
                .execute(&mut **tx)
                .await?;
            Ok(())
        },
        |tx| {
            sqlx::query!("/* postgres */ delete from t_checklist_document where project_id = $1", project_id)
                .execute(&mut **tx)
                .await?;
            Ok(())
        },
    )
}

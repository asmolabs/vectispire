//! `t_checklist_template`, `t_checklist_template_version` and `t_checklist_item` (V51).

use vectispire_cp_db::Tx;
use vectispire_cp_db::types::UtcInstant;

use super::{StoreError, engines};

/// A row of `t_checklist_template`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TemplateRow {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub created_at: UtcInstant,
    pub created_by: String,
}

/// A row of `t_checklist_template_version` without its workbook, which [`source_bytes`] reads when a caller needs it:
/// a summary, a status check and a view of the items have no use for megabytes of `.xlsx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VersionRow {
    pub id: i64,
    pub template_id: i64,
    pub ordinal: i32,
    pub label: Option<String>,
    pub status: String,
    pub revision: i32,
    pub source_sha256: String,
    pub source_size: i64,
    pub layout: Option<String>,
    pub offers_not_applicable: bool,
    pub item_pairs: Option<String>,
    pub previous_version_id: Option<i64>,
    pub derived_from_version_id: Option<i64>,
    pub draft_authors: String,
    pub imported_at: UtcInstant,
    pub imported_by: String,
    pub published_at: Option<UtcInstant>,
    pub published_by: Option<String>,
    pub retired_at: Option<UtcInstant>,
    pub retired_by: Option<String>,
}

/// `ChecklistTemplateVersionSummary`: a version and how many items it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SummaryRow {
    pub version: VersionRow,
    pub item_count: i64,
}

/// A new version's row, before its identity.
#[derive(Debug, Clone)]
pub(crate) struct NewVersion<'a> {
    pub template_id: i64,
    pub ordinal: i32,
    pub label: Option<&'a str>,
    pub status: &'a str,
    pub revision: i32,
    pub source_sha256: &'a str,
    pub source_size: i64,
    pub source_bytes: &'a [u8],
    pub layout: Option<&'a str>,
    pub offers_not_applicable: bool,
    pub previous_version_id: Option<i64>,
    pub derived_from_version_id: Option<i64>,
    pub draft_authors: &'a str,
    pub imported_at: UtcInstant,
    pub imported_by: &'a str,
}

/// A row of `t_checklist_item`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRow {
    pub id: i64,
    pub version_id: i64,
    pub item_key: String,
    pub position: i32,
    pub domain: String,
    pub objective: String,
    pub control: String,
    pub contact: String,
    pub kpi: String,
    pub content_digest: String,
    pub sheet_row: i32,
    pub evidence_kind: String,
    pub evidence_validity_months: Option<i32>,
    pub bound_rule: Option<String>,
}

// ------------------------------------------------------------------ templates

pub(crate) async fn template_by_slug(tx: &mut Tx, slug: &str) -> Result<Option<TemplateRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_as!(
            TemplateRow,
            r#"/* mysql */ select id, slug, name, created_at as "created_at: UtcInstant", created_by
               from t_checklist_template where slug = ?"#,
            slug
        )
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_as!(
            TemplateRow,
            r#"/* postgres */ select id, slug, name, created_at as "created_at: UtcInstant", created_by
               from t_checklist_template where slug = $1"#,
            slug
        )
        .fetch_optional(&mut **tx)
        .await?),
    )
}

pub(crate) async fn template_by_id(tx: &mut Tx, id: i64) -> Result<Option<TemplateRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_as!(
            TemplateRow,
            r#"/* mysql */ select id, slug, name, created_at as "created_at: UtcInstant", created_by
               from t_checklist_template where id = ?"#,
            id
        )
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_as!(
            TemplateRow,
            r#"/* postgres */ select id, slug, name, created_at as "created_at: UtcInstant", created_by
               from t_checklist_template where id = $1"#,
            id
        )
        .fetch_optional(&mut **tx)
        .await?),
    )
}

/// `findAllByOrderBySlugAsc`. The slug's ascending order is the engine's collation's, as Java's was.
pub(crate) async fn templates_by_slug(tx: &mut Tx) -> Result<Vec<TemplateRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_as!(
            TemplateRow,
            r#"/* mysql */ select id, slug, name, created_at as "created_at: UtcInstant", created_by
               from t_checklist_template order by slug asc"#
        )
        .fetch_all(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_as!(
            TemplateRow,
            r#"/* postgres */ select id, slug, name, created_at as "created_at: UtcInstant", created_by
               from t_checklist_template order by slug asc"#
        )
        .fetch_all(&mut **tx)
        .await?),
    )
}

pub(crate) async fn insert_template(
    tx: &mut Tx,
    slug: &str,
    name: &str,
    created_at: UtcInstant,
    created_by: &str,
) -> Result<i64, StoreError> {
    engines!(
        tx,
        |tx| {
            let done = sqlx::query!(
                "/* mysql */ insert into t_checklist_template (slug, name, created_at, created_by) values (?, ?, ?, ?)",
                slug,
                name,
                created_at,
                created_by
            )
            .execute(&mut **tx)
            .await?;
            super::inserted(&done)
        },
        |tx| Ok(sqlx::query_scalar!(
            "/* postgres */ insert into t_checklist_template (slug, name, created_at, created_by) \
             values ($1, $2, $3, $4) returning id",
            slug,
            name,
            created_at as UtcInstant,
            created_by
        )
        .fetch_one(&mut **tx)
        .await?),
    )
}

// ------------------------------------------------------------------ versions

pub(crate) async fn version_by_id(tx: &mut Tx, id: i64) -> Result<Option<VersionRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_as!(
            VersionRow,
            r#"/* mysql */ select id, template_id, ordinal, label, status, revision, source_sha256, source_size, layout,
               offers_not_applicable as "offers_not_applicable: bool", item_pairs, previous_version_id,
               derived_from_version_id, draft_authors, imported_at as "imported_at: UtcInstant", imported_by,
               published_at as "published_at: UtcInstant", published_by, retired_at as "retired_at: UtcInstant",
               retired_by from t_checklist_template_version where id = ?"#,
            id
        )
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_as!(
            VersionRow,
            r#"/* postgres */ select id, template_id, ordinal, label, status, revision, source_sha256, source_size,
               layout, offers_not_applicable, item_pairs, previous_version_id, derived_from_version_id, draft_authors,
               imported_at as "imported_at: UtcInstant", imported_by, published_at as "published_at: UtcInstant",
               published_by, retired_at as "retired_at: UtcInstant", retired_by
               from t_checklist_template_version where id = $1"#,
            id
        )
        .fetch_optional(&mut **tx)
        .await?),
    )
}

pub(crate) async fn version_by_ordinal(
    tx: &mut Tx,
    template_id: i64,
    ordinal: i32,
) -> Result<Option<VersionRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_as!(
            VersionRow,
            r#"/* mysql */ select id, template_id, ordinal, label, status, revision, source_sha256, source_size, layout,
               offers_not_applicable as "offers_not_applicable: bool", item_pairs, previous_version_id,
               derived_from_version_id, draft_authors, imported_at as "imported_at: UtcInstant", imported_by,
               published_at as "published_at: UtcInstant", published_by, retired_at as "retired_at: UtcInstant",
               retired_by from t_checklist_template_version where template_id = ? and ordinal = ?"#,
            template_id,
            ordinal
        )
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_as!(
            VersionRow,
            r#"/* postgres */ select id, template_id, ordinal, label, status, revision, source_sha256, source_size,
               layout, offers_not_applicable, item_pairs, previous_version_id, derived_from_version_id, draft_authors,
               imported_at as "imported_at: UtcInstant", imported_by, published_at as "published_at: UtcInstant",
               published_by, retired_at as "retired_at: UtcInstant", retired_by
               from t_checklist_template_version where template_id = $1 and ordinal = $2"#,
            template_id,
            ordinal
        )
        .fetch_optional(&mut **tx)
        .await?),
    )
}

/// The workbook a version was imported from, as stored.
pub(crate) async fn source_bytes(tx: &mut Tx, version_id: i64) -> Result<Option<Vec<u8>>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_scalar!(
            "/* mysql */ select source_bytes from t_checklist_template_version where id = ?",
            version_id
        )
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_scalar!(
            "/* postgres */ select source_bytes from t_checklist_template_version where id = $1",
            version_id
        )
        .fetch_optional(&mut **tx)
        .await?),
    )
}

/// `summariesOf`: every version of a template, by number, each with its item count.
pub(crate) async fn summaries_of(tx: &mut Tx, template_id: i64) -> Result<Vec<SummaryRow>, StoreError> {
    let versions = versions_of(tx, template_id).await?;
    let counts: std::collections::HashMap<i64, i64> = item_counts(tx, template_id).await?.into_iter().collect();
    Ok(versions
        .into_iter()
        .map(|version| {
            let item_count = counts.get(&version.id).copied().unwrap_or(0);
            SummaryRow { version, item_count }
        })
        .collect())
}

/// Every version of a template, by number.
async fn versions_of(tx: &mut Tx, template_id: i64) -> Result<Vec<VersionRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_as!(
            VersionRow,
            r#"/* mysql */ select id, template_id, ordinal, label, status, revision, source_sha256, source_size, layout,
               offers_not_applicable as "offers_not_applicable: bool", item_pairs, previous_version_id,
               derived_from_version_id, draft_authors, imported_at as "imported_at: UtcInstant", imported_by,
               published_at as "published_at: UtcInstant", published_by, retired_at as "retired_at: UtcInstant",
               retired_by from t_checklist_template_version where template_id = ? order by ordinal asc"#,
            template_id
        )
        .fetch_all(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_as!(
            VersionRow,
            r#"/* postgres */ select id, template_id, ordinal, label, status, revision, source_sha256, source_size,
               layout, offers_not_applicable, item_pairs, previous_version_id, derived_from_version_id, draft_authors,
               imported_at as "imported_at: UtcInstant", imported_by, published_at as "published_at: UtcInstant",
               published_by, retired_at as "retired_at: UtcInstant", retired_by
               from t_checklist_template_version where template_id = $1 order by ordinal asc"#,
            template_id
        )
        .fetch_all(&mut **tx)
        .await?),
    )
}

/// How many items each version of a template has; a version with none is missing.
async fn item_counts(tx: &mut Tx, template_id: i64) -> Result<Vec<(i64, i64)>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query!(
            r#"/* mysql */ select version_id, count(*) as "n!: i64" from t_checklist_item where version_id in
               (select id from t_checklist_template_version where template_id = ?) group by version_id"#,
            template_id
        )
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .map(|row| (row.version_id, row.n))
        .collect()),
        |tx| Ok(sqlx::query!(
            r#"/* postgres */ select version_id, count(*) as "n!: i64" from t_checklist_item where version_id in
               (select id from t_checklist_template_version where template_id = $1) group by version_id"#,
            template_id
        )
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .map(|row| (row.version_id, row.n))
        .collect()),
    )
}

/// `existsByTemplateIdAndStatus`.
pub(crate) async fn has_version_in(tx: &mut Tx, template_id: i64, status: &str) -> Result<bool, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_scalar!(
            r#"/* mysql */ select count(*) as "n!: i64" from t_checklist_template_version
               where template_id = ? and status = ?"#,
            template_id,
            status
        )
        .fetch_one(&mut **tx)
        .await?
            > 0),
        |tx| Ok(sqlx::query_scalar!(
            r#"/* postgres */ select count(*) as "n!: i64" from t_checklist_template_version
               where template_id = $1 and status = $2"#,
            template_id,
            status
        )
        .fetch_one(&mut **tx)
        .await?
            > 0),
    )
}

/// `lastOrdinal`: the highest number a template's versions took, 0 for none.
pub(crate) async fn last_ordinal(tx: &mut Tx, template_id: i64) -> Result<i64, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_scalar!(
            r#"/* mysql */ select cast(coalesce(max(ordinal), 0) as signed) as "n!: i64"
               from t_checklist_template_version where template_id = ?"#,
            template_id
        )
        .fetch_one(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_scalar!(
            r#"/* postgres */ select coalesce(max(ordinal), 0)::bigint as "n!: i64"
               from t_checklist_template_version where template_id = $1"#,
            template_id
        )
        .fetch_one(&mut **tx)
        .await?),
    )
}

/// `publishedNewestFirst`: the versions ever published — retired ones included — newest number first.
pub(crate) async fn published_newest_first(tx: &mut Tx, template_id: i64) -> Result<Vec<i64>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_scalar!(
            "/* mysql */ select id from t_checklist_template_version where template_id = ? \
             and published_at is not null order by ordinal desc",
            template_id
        )
        .fetch_all(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_scalar!(
            "/* postgres */ select id from t_checklist_template_version where template_id = $1 \
             and published_at is not null order by ordinal desc",
            template_id
        )
        .fetch_all(&mut **tx)
        .await?),
    )
}

pub(crate) async fn insert_version(tx: &mut Tx, version: &NewVersion<'_>) -> Result<i64, StoreError> {
    let v = version;
    engines!(
        tx,
        |tx| {
            let done = sqlx::query!(
                "/* mysql */ insert into t_checklist_template_version (template_id, ordinal, label, status, revision, \
                 source_sha256, source_size, source_bytes, layout, offers_not_applicable, item_pairs, \
                 previous_version_id, derived_from_version_id, draft_authors, imported_at, imported_by) \
                 values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null, ?, ?, ?, ?, ?)",
                v.template_id,
                v.ordinal,
                v.label,
                v.status,
                v.revision,
                v.source_sha256,
                v.source_size,
                v.source_bytes,
                v.layout,
                v.offers_not_applicable,
                v.previous_version_id,
                v.derived_from_version_id,
                v.draft_authors,
                v.imported_at,
                v.imported_by
            )
            .execute(&mut **tx)
            .await?;
            super::inserted(&done)
        },
        |tx| Ok(sqlx::query_scalar!(
            "/* postgres */ insert into t_checklist_template_version (template_id, ordinal, label, status, revision, \
             source_sha256, source_size, source_bytes, layout, offers_not_applicable, item_pairs, \
             previous_version_id, derived_from_version_id, draft_authors, imported_at, imported_by) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, null, $11, $12, $13, $14, $15) returning id",
            v.template_id,
            v.ordinal,
            v.label,
            v.status,
            v.revision,
            v.source_sha256,
            v.source_size,
            v.source_bytes,
            v.layout,
            v.offers_not_applicable,
            v.previous_version_id,
            v.derived_from_version_id,
            v.draft_authors,
            v.imported_at as UtcInstant,
            v.imported_by
        )
        .fetch_one(&mut **tx)
        .await?),
    )
}

/// What a draft's edit writes, behind the revision its writer read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DraftEdit<'a> {
    pub layout: Option<&'a str>,
    pub offers_not_applicable: bool,
    pub item_pairs: Option<&'a str>,
    pub draft_authors: &'a str,
}

/// `editDraft`: the conditional update on the revision read; the rows it touched, 1 or 0.
pub(crate) async fn edit_draft(
    tx: &mut Tx,
    id: i64,
    revision: i32,
    draft: &str,
    edit: DraftEdit<'_>,
) -> Result<u64, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query!(
            "/* mysql */ update t_checklist_template_version set revision = revision + 1, layout = ?, \
             offers_not_applicable = ?, item_pairs = ?, draft_authors = ? where id = ? and status = ? and revision = ?",
            edit.layout,
            edit.offers_not_applicable,
            edit.item_pairs,
            edit.draft_authors,
            id,
            draft,
            revision
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
        |tx| Ok(sqlx::query!(
            "/* postgres */ update t_checklist_template_version set revision = revision + 1, layout = $1, \
             offers_not_applicable = $2, item_pairs = $3, draft_authors = $4 \
             where id = $5 and status = $6 and revision = $7",
            edit.layout,
            edit.offers_not_applicable,
            edit.item_pairs,
            edit.draft_authors,
            id,
            draft,
            revision
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
    )
}

/// `publish`: a draft at the revision reviewed becomes published.
pub(crate) async fn publish_version(
    tx: &mut Tx,
    id: i64,
    revision: i32,
    draft: &str,
    published: &str,
    at: UtcInstant,
    by: &str,
) -> Result<u64, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query!(
            "/* mysql */ update t_checklist_template_version set status = ?, revision = revision + 1, \
             published_at = ?, published_by = ? where id = ? and status = ? and revision = ?",
            published,
            at,
            by,
            id,
            draft,
            revision
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
        |tx| Ok(sqlx::query!(
            "/* postgres */ update t_checklist_template_version set status = $1, revision = revision + 1, \
             published_at = $2, published_by = $3 where id = $4 and status = $5 and revision = $6",
            published,
            at as UtcInstant,
            by,
            id,
            draft,
            revision
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
    )
}

/// `retire`: from the status read, at the revision read.
pub(crate) async fn retire_version(
    tx: &mut Tx,
    id: i64,
    revision: i32,
    from: &str,
    retired: &str,
    at: UtcInstant,
    by: &str,
) -> Result<u64, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query!(
            "/* mysql */ update t_checklist_template_version set status = ?, revision = revision + 1, \
             retired_at = ?, retired_by = ? where id = ? and status = ? and revision = ?",
            retired,
            at,
            by,
            id,
            from,
            revision
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
        |tx| Ok(sqlx::query!(
            "/* postgres */ update t_checklist_template_version set status = $1, revision = revision + 1, \
             retired_at = $2, retired_by = $3 where id = $4 and status = $5 and revision = $6",
            retired,
            at as UtcInstant,
            by,
            id,
            from,
            revision
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
    )
}

// ------------------------------------------------------------------ items

/// `findByVersionIdOrderByPositionAsc`.
pub(crate) async fn items_of(tx: &mut Tx, version_id: i64) -> Result<Vec<ItemRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_as!(
            ItemRow,
            r#"/* mysql */ select id, version_id, item_key, item_position as position, domain, objective, control,
               contact, kpi, content_digest, sheet_row, evidence_kind, evidence_validity_months, bound_rule
               from t_checklist_item where version_id = ? order by item_position asc"#,
            version_id
        )
        .fetch_all(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_as!(
            ItemRow,
            r#"/* postgres */ select id, version_id, item_key, item_position as position, domain, objective, control,
               contact, kpi, content_digest, sheet_row, evidence_kind, evidence_validity_months, bound_rule
               from t_checklist_item where version_id = $1 order by item_position asc"#,
            version_id
        )
        .fetch_all(&mut **tx)
        .await?),
    )
}

pub(crate) async fn item_by_id(tx: &mut Tx, id: i64) -> Result<Option<ItemRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_as!(
            ItemRow,
            r#"/* mysql */ select id, version_id, item_key, item_position as position, domain, objective, control,
               contact, kpi, content_digest, sheet_row, evidence_kind, evidence_validity_months, bound_rule
               from t_checklist_item where id = ?"#,
            id
        )
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_as!(
            ItemRow,
            r#"/* postgres */ select id, version_id, item_key, item_position as position, domain, objective, control,
               contact, kpi, content_digest, sheet_row, evidence_kind, evidence_validity_months, bound_rule
               from t_checklist_item where id = $1"#,
            id
        )
        .fetch_optional(&mut **tx)
        .await?),
    )
}

/// `deleteByVersion`.
pub(crate) async fn delete_items(tx: &mut Tx, version_id: i64) -> Result<(), StoreError> {
    engines!(
        tx,
        |tx| {
            sqlx::query!("/* mysql */ delete from t_checklist_item where version_id = ?", version_id)
                .execute(&mut **tx)
                .await?;
            Ok(())
        },
        |tx| {
            sqlx::query!("/* postgres */ delete from t_checklist_item where version_id = $1", version_id)
                .execute(&mut **tx)
                .await?;
            Ok(())
        },
    )
}

/// An item's row before its identity; `id` is ignored.
pub(crate) async fn insert_item(tx: &mut Tx, item: &ItemRow) -> Result<i64, StoreError> {
    let i = item;
    engines!(
        tx,
        |tx| {
            let done = sqlx::query!(
                "/* mysql */ insert into t_checklist_item (version_id, item_key, item_position, domain, objective, \
                 control, contact, kpi, content_digest, sheet_row, evidence_kind, evidence_validity_months, bound_rule) \
                 values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                i.version_id,
                i.item_key,
                i.position,
                i.domain,
                i.objective,
                i.control,
                i.contact,
                i.kpi,
                i.content_digest,
                i.sheet_row,
                i.evidence_kind,
                i.evidence_validity_months,
                i.bound_rule
            )
            .execute(&mut **tx)
            .await?;
            super::inserted(&done)
        },
        |tx| Ok(sqlx::query_scalar!(
            "/* postgres */ insert into t_checklist_item (version_id, item_key, item_position, domain, objective, \
             control, contact, kpi, content_digest, sheet_row, evidence_kind, evidence_validity_months, bound_rule) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) returning id",
            i.version_id,
            i.item_key,
            i.position,
            i.domain,
            i.objective,
            i.control,
            i.contact,
            i.kpi,
            i.content_digest,
            i.sheet_row,
            i.evidence_kind,
            i.evidence_validity_months,
            i.bound_rule
        )
        .fetch_one(&mut **tx)
        .await?),
    )
}

/// What `items.saveAll(changed)` writes of a line whose requirement or binding moved: the requirement, the binding
/// and the digest over both.
pub(crate) async fn update_item_terms(tx: &mut Tx, item: &ItemRow) -> Result<(), StoreError> {
    let i = item;
    engines!(
        tx,
        |tx| {
            sqlx::query!(
                "/* mysql */ update t_checklist_item set evidence_kind = ?, evidence_validity_months = ?, \
                 bound_rule = ?, content_digest = ? where id = ?",
                i.evidence_kind,
                i.evidence_validity_months,
                i.bound_rule,
                i.content_digest,
                i.id
            )
            .execute(&mut **tx)
            .await?;
            Ok(())
        },
        |tx| {
            sqlx::query!(
                "/* postgres */ update t_checklist_item set evidence_kind = $1, evidence_validity_months = $2, \
                 bound_rule = $3, content_digest = $4 where id = $5",
                i.evidence_kind,
                i.evidence_validity_months,
                i.bound_rule,
                i.content_digest,
                i.id
            )
            .execute(&mut **tx)
            .await?;
            Ok(())
        },
    )
}

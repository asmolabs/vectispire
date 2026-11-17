//! `t_checklist_contact` (V91): a project's checklist profiles linked to accounts.

use vectispire_cp_db::Tx;
use vectispire_cp_db::types::UtcInstant;

use super::{StoreError, engines};

/// A row of `t_checklist_contact`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContactRow {
    pub id: i64,
    pub project_id: i64,
    pub profile: String,
    pub account_id: i64,
    pub linked_by: String,
    pub linked_at: UtcInstant,
}

/// `findByProjectIdOrderByProfileAsc`.
pub(crate) async fn contacts_of(tx: &mut Tx, project_id: i64) -> Result<Vec<ContactRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_as!(
            ContactRow,
            r#"/* mysql */ select id, project_id, profile, account_id, linked_by, linked_at as "linked_at: UtcInstant"
               from t_checklist_contact where project_id = ? order by profile asc"#,
            project_id
        )
        .fetch_all(&mut **tx)
        .await?),
        |tx| {
            Ok(sqlx::query_as!(
            ContactRow,
            r#"/* postgres */ select id, project_id, profile, account_id, linked_by,
               linked_at as "linked_at: UtcInstant" from t_checklist_contact where project_id = $1 order by profile asc"#,
            project_id
        )
        .fetch_all(&mut **tx)
        .await?)
        },
    )
}

/// `findByProjectIdAndProfile`.
pub(crate) async fn contact_of(tx: &mut Tx, project_id: i64, profile: &str) -> Result<Option<ContactRow>, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query_as!(
            ContactRow,
            r#"/* mysql */ select id, project_id, profile, account_id, linked_by, linked_at as "linked_at: UtcInstant"
               from t_checklist_contact where project_id = ? and profile = ?"#,
            project_id,
            profile
        )
        .fetch_optional(&mut **tx)
        .await?),
        |tx| Ok(sqlx::query_as!(
            ContactRow,
            r#"/* postgres */ select id, project_id, profile, account_id, linked_by,
               linked_at as "linked_at: UtcInstant" from t_checklist_contact where project_id = $1 and profile = $2"#,
            project_id,
            profile
        )
        .fetch_optional(&mut **tx)
        .await?),
    )
}

pub(crate) async fn insert_contact(
    tx: &mut Tx,
    project_id: i64,
    profile: &str,
    account_id: i64,
    linked_by: &str,
    linked_at: UtcInstant,
) -> Result<i64, StoreError> {
    engines!(
        tx,
        |tx| {
            let done = sqlx::query!(
                "/* mysql */ insert into t_checklist_contact (project_id, profile, account_id, linked_by, linked_at) \
                 values (?, ?, ?, ?, ?)",
                project_id,
                profile,
                account_id,
                linked_by,
                linked_at
            )
            .execute(&mut **tx)
            .await?;
            super::inserted(&done)
        },
        |tx| Ok(sqlx::query_scalar!(
            "/* postgres */ insert into t_checklist_contact (project_id, profile, account_id, linked_by, linked_at) \
             values ($1, $2, $3, $4, $5) returning id",
            project_id,
            profile,
            account_id,
            linked_by,
            linked_at as UtcInstant
        )
        .fetch_one(&mut **tx)
        .await?),
    )
}

/// The link of an existing row replaced: `save` on a found entity.
pub(crate) async fn update_contact(
    tx: &mut Tx,
    id: i64,
    account_id: i64,
    linked_by: &str,
    linked_at: UtcInstant,
) -> Result<(), StoreError> {
    engines!(
        tx,
        |tx| {
            sqlx::query!(
                "/* mysql */ update t_checklist_contact set account_id = ?, linked_by = ?, linked_at = ? where id = ?",
                account_id,
                linked_by,
                linked_at,
                id
            )
            .execute(&mut **tx)
            .await?;
            Ok(())
        },
        |tx| {
            sqlx::query!(
                "/* postgres */ update t_checklist_contact set account_id = $1, linked_by = $2, linked_at = $3 \
                 where id = $4",
                account_id,
                linked_by,
                linked_at as UtcInstant,
                id
            )
            .execute(&mut **tx)
            .await?;
            Ok(())
        },
    )
}

/// `deleteLink`: the rows removed.
pub(crate) async fn delete_contact(tx: &mut Tx, project_id: i64, profile: &str) -> Result<u64, StoreError> {
    engines!(
        tx,
        |tx| Ok(sqlx::query!(
            "/* mysql */ delete from t_checklist_contact where project_id = ? and profile = ?",
            project_id,
            profile
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
        |tx| Ok(sqlx::query!(
            "/* postgres */ delete from t_checklist_contact where project_id = $1 and profile = $2",
            project_id,
            profile
        )
        .execute(&mut **tx)
        .await?
        .rows_affected()),
    )
}

pub(crate) async fn delete_contacts_of_project(tx: &mut Tx, project_id: i64) -> Result<(), StoreError> {
    engines!(
        tx,
        |tx| {
            sqlx::query!("/* mysql */ delete from t_checklist_contact where project_id = ?", project_id)
                .execute(&mut **tx)
                .await?;
            Ok(())
        },
        |tx| {
            sqlx::query!("/* postgres */ delete from t_checklist_contact where project_id = $1", project_id)
                .execute(&mut **tx)
                .await?;
            Ok(())
        },
    )
}

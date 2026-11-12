//! The second factor's columns of `t_user` — `UserRepository.advanceTotpStep`, `replaceBackupCodes`, the enrolment
//! counts, and what `TotpService` saves when a factor is enabled or disabled.
//!
//! **Enabling and disabling write the columns Java changes, and only those.** `TotpService` saves the whole entity it
//! loaded at the start of the request, so a role change or a deactivation committed in between was written back as it
//! was; here the statement names `mfa_enabled`, `totp_secret`, `mfa_backup_codes`, `totp_last_step` and `updated_at`.
//! The same difference on purpose as the password's rehash (`users.rs`).

use time::OffsetDateTime;
use vectispire_cp_db::Db;
use vectispire_cp_db::types::to_microseconds;

use super::Enrolled;
use crate::persistence::model::StoreError;

/// `advanceTotpStep`: the comparison is the update's, so two presentations of one code cannot both pass a check
/// made before the write.
pub(super) async fn advance_step(db: &Db, user_id: i64, step: i64) -> Result<u64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!(
            "/* mysql */ update t_user set totp_last_step = ? where id = ? \
             and (totp_last_step is null or totp_last_step < ?)",
            step,
            user_id,
            step
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!(
            "/* postgres */ update t_user set totp_last_step = $1 where id = $2 \
             and (totp_last_step is null or totp_last_step < $1)",
            step,
            user_id
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// `replaceBackupCodes`: the ciphertext read is the version — of two sign-ins spending one code, only one update
/// still finds it.
pub(super) async fn replace_backup_codes(
    db: &Db,
    user_id: i64,
    expected: &str,
    replacement: &str,
    at: OffsetDateTime,
) -> Result<u64, StoreError> {
    let at = to_microseconds(at);
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!(
            "/* mysql */ update t_user set mfa_backup_codes = ?, updated_at = ? where id = ? and mfa_backup_codes = ?",
            replacement,
            at,
            user_id,
            expected
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!(
            "/* postgres */ update t_user set mfa_backup_codes = $1, updated_at = $2 \
             where id = $3 and mfa_backup_codes = $4",
            replacement,
            at,
            user_id,
            expected
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// What `TotpService.enable` sets before `save`.
pub(super) async fn enable(db: &Db, user_id: i64, enrolled: &Enrolled) -> Result<(), StoreError> {
    let at = to_microseconds(enrolled.at);
    match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!(
                "/* mysql */ update t_user set mfa_enabled = true, totp_secret = ?, mfa_backup_codes = ?, \
                 totp_last_step = ?, updated_at = ? where id = ?",
                enrolled.totp_secret,
                enrolled.backup_codes,
                enrolled.last_step,
                at,
                user_id
            )
            .execute(pool)
            .await?;
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!(
                "/* postgres */ update t_user set mfa_enabled = true, totp_secret = $1, mfa_backup_codes = $2, \
                 totp_last_step = $3, updated_at = $4 where id = $5",
                enrolled.totp_secret,
                enrolled.backup_codes,
                enrolled.last_step,
                at,
                user_id
            )
            .execute(pool)
            .await?;
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    }
    Ok(())
}

/// What `TotpService.disable` sets before `save`.
pub(super) async fn disable(db: &Db, user_id: i64, at: OffsetDateTime) -> Result<(), StoreError> {
    let at = to_microseconds(at);
    match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!(
                "/* mysql */ update t_user set mfa_enabled = false, totp_secret = null, mfa_backup_codes = null, \
                 totp_last_step = null, updated_at = ? where id = ?",
                at,
                user_id
            )
            .execute(pool)
            .await?;
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!(
                "/* postgres */ update t_user set mfa_enabled = false, totp_secret = null, mfa_backup_codes = null, \
                 totp_last_step = null, updated_at = $1 where id = $2",
                at,
                user_id
            )
            .execute(pool)
            .await?;
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    }
    Ok(())
}

/// `countActiveWithPassword`.
pub(super) async fn count_with_password(db: &Db) -> Result<i64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query_scalar!(
            r#"/* mysql */ select count(*) as "n!: i64" from t_user where is_active = true and password is not null"#
        )
        .fetch_one(pool)
        .await?,
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query_scalar!(
                r#"/* postgres */ select count(*) as "n!" from t_user where is_active = true and password is not null"#
            )
            .fetch_one(pool)
            .await?
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// `countActiveWithPasswordAndNoSecondFactor`.
pub(super) async fn count_with_password_and_no_second_factor(db: &Db) -> Result<i64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query_scalar!(
                r#"/* mysql */ select count(*) as "n!: i64" from t_user
            where is_active = true and password is not null and mfa_enabled = false"#
            )
            .fetch_one(pool)
            .await?
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query_scalar!(
                r#"/* postgres */ select count(*) as "n!" from t_user
            where is_active = true and password is not null and mfa_enabled = false"#
            )
            .fetch_one(pool)
            .await?
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

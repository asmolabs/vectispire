//! `t_account_administration` and `t_account_request` (V100) on either engine — `AccountAdministrationRepository` and
//! `AccountRequestRepository`, and the row locks four-eyes takes on `t_user` and on a request.
//!
//! Checked statements per engine, as `users.rs` writes them, but for the two `in (…)` lists whose length is the
//! caller's list of roles: on MySQL those are built from placeholders, as `users.rs` says why.

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Tx};

use crate::persistence::model::{AccountRequest, Gesture, NewAccountRequest, StoreError};

/// The gestures `administrator_id` made on `account_id` since `since`, newest first, as stored.
pub(crate) async fn gestures_since(
    db: &Db,
    account_id: i64,
    administrator_id: i64,
    since: OffsetDateTime,
) -> Result<Vec<String>, StoreError> {
    match db {
        Db::MySql(pool) => mysql::gestures_since(pool, account_id, administrator_id, since).await,
        Db::PostgreSql(pool) => postgres::gestures_since(pool, account_id, administrator_id, since).await,
    }
}

/// `anyChangedFromSince`: a gesture of this kind out of one of `roles`, since `since`, on an account other than
/// `excluding`.
pub(crate) async fn any_changed_from_since(
    db: &Db,
    gesture: Gesture,
    roles: &[&str],
    since: OffsetDateTime,
    excluding: i64,
) -> Result<bool, StoreError> {
    if roles.is_empty() {
        return Ok(false);
    }
    match db {
        Db::MySql(pool) => mysql::any_changed_from_since(pool, gesture.wire_name(), roles, since, excluding).await,
        Db::PostgreSql(pool) => {
            postgres::any_changed_from_since(pool, gesture.wire_name(), roles, since, excluding).await
        }
    }
}

/// `countAdministratorsExcluding`: active or not.
pub(crate) async fn count_other_admins(db: &Db, roles: &[&str], excluding: i64) -> Result<i64, StoreError> {
    if roles.is_empty() {
        return Ok(0);
    }
    match db {
        Db::MySql(pool) => mysql::count_other_admins(pool, roles, excluding).await,
        Db::PostgreSql(pool) => postgres::count_other_admins(pool, roles, excluding).await,
    }
}

pub(crate) async fn record_gesture(
    tx: &mut Tx,
    account_id: i64,
    administrator_id: i64,
    gesture: Gesture,
    held_role: Option<&str>,
    at: OffsetDateTime,
) -> Result<(), StoreError> {
    match tx {
        Tx::MySql(tx) => {
            mysql::record_gesture(tx, account_id, administrator_id, gesture.wire_name(), held_role, at).await
        }
        Tx::PostgreSql(tx) => {
            postgres::record_gesture(tx, account_id, administrator_id, gesture.wire_name(), held_role, at).await
        }
    }
}

/// `users.findByUsername`, as the database's collation compares names: the account's id and stored name.
pub(crate) async fn account_named(db: &Db, username: &str) -> Result<Option<(i64, String)>, StoreError> {
    match db {
        Db::MySql(pool) => mysql::account_named(pool, username).await,
        Db::PostgreSql(pool) => postgres::account_named(pool, username).await,
    }
}

pub(crate) async fn requests_in(db: &Db, status: &str) -> Result<Vec<AccountRequest>, StoreError> {
    match db {
        Db::MySql(pool) => mysql::requests_in(pool, status).await,
        Db::PostgreSql(pool) => postgres::requests_in(pool, status).await,
    }
}

pub(crate) async fn find_request(db: &Db, id: i64) -> Result<Option<AccountRequest>, StoreError> {
    match db {
        Db::MySql(pool) => mysql::find_request(pool, id).await,
        Db::PostgreSql(pool) => postgres::find_request(pool, id).await,
    }
}

pub(crate) async fn pending_for(db: &Db, account_id: i64) -> Result<bool, StoreError> {
    match db {
        Db::MySql(pool) => mysql::pending_for(pool, account_id).await,
        Db::PostgreSql(pool) => postgres::pending_for(pool, account_id).await,
    }
}

/// `select … for update` on one request, held until the transaction ends.
pub(crate) async fn lock_request(tx: &mut Tx, id: i64) -> Result<Option<AccountRequest>, StoreError> {
    match tx {
        Tx::MySql(tx) => mysql::lock_request(tx, id).await,
        Tx::PostgreSql(tx) => postgres::lock_request(tx, id).await,
    }
}

/// `users.lockById`: the account's role, its row locked until the transaction ends; `None` when it is gone.
pub(crate) async fn lock_account(tx: &mut Tx, id: i64) -> Result<Option<String>, StoreError> {
    match tx {
        Tx::MySql(tx) => mysql::lock_account(tx, id).await,
        Tx::PostgreSql(tx) => postgres::lock_account(tx, id).await,
    }
}

pub(crate) async fn pending_for_in(tx: &mut Tx, account_id: i64) -> Result<bool, StoreError> {
    match tx {
        Tx::MySql(tx) => mysql::pending_for_in(tx, account_id).await,
        Tx::PostgreSql(tx) => postgres::pending_for_in(tx, account_id).await,
    }
}

pub(crate) async fn creation_pending(tx: &mut Tx, username: &str) -> Result<bool, StoreError> {
    match tx {
        Tx::MySql(tx) => mysql::creation_pending(tx, username).await,
        Tx::PostgreSql(tx) => postgres::creation_pending(tx, username).await,
    }
}

pub(crate) async fn insert_request(tx: &mut Tx, request: &NewAccountRequest) -> Result<i64, StoreError> {
    match tx {
        Tx::MySql(tx) => mysql::insert_request(tx, request).await,
        Tx::PostgreSql(tx) => postgres::insert_request(tx, request).await,
    }
}

/// The decision, and the hash cleared: the request keeps no copy of a password the account now holds, or never will.
pub(crate) async fn decide(
    tx: &mut Tx,
    id: i64,
    status: &str,
    decided_by: &str,
    decided_at: OffsetDateTime,
) -> Result<(), StoreError> {
    match tx {
        Tx::MySql(tx) => mysql::decide(tx, id, status, decided_by, decided_at).await,
        Tx::PostgreSql(tx) => postgres::decide(tx, id, status, decided_by, decided_at).await,
    }
}

/// A row of either engine's checked `select` of `t_account_request`.
macro_rules! request_from {
    ($row:expr) => {{
        let row = $row;
        AccountRequest {
            id: row.id,
            kind: row.kind,
            status: row.status,
            account_id: row.account_id,
            username: row.username,
            email: row.email,
            display_name: row.display_name,
            held_role: row.held_role,
            requested_role: row.requested_role,
            password_hash: row.password_hash.map(PasswordHash::new),
            requested_by_id: row.requested_by_id,
            requested_by: row.requested_by,
            requested_at: row.requested_at.0,
            decided_by: row.decided_by,
            decided_at: row.decided_at.map(|at| at.0),
        }
    }};
}

#[cfg(feature = "mysql-queries")]
mod mysql {
    use sqlx::{MySqlConnection, MySqlPool};
    use time::OffsetDateTime;
    use vectispire_cp_db::types::UtcInstant;

    use crate::persistence::model::{AccountRequest, NewAccountRequest, PasswordHash, StoreError};

    pub(super) async fn gestures_since(
        pool: &MySqlPool,
        account_id: i64,
        administrator_id: i64,
        since: OffsetDateTime,
    ) -> Result<Vec<String>, StoreError> {
        Ok(sqlx::query_scalar!(
            "/* mysql */ select gesture from t_account_administration where account_id = ? and administrator_id = ? \
             and occurred_at >= ? order by occurred_at desc",
            account_id,
            administrator_id,
            UtcInstant(since)
        )
        .fetch_all(pool)
        .await?)
    }

    /// Built from placeholders: one per role, nothing of the caller's text (`users.rs` says why it is not checked).
    pub(super) async fn any_changed_from_since(
        pool: &MySqlPool,
        gesture: &str,
        roles: &[&str],
        since: OffsetDateTime,
        excluding: i64,
    ) -> Result<bool, StoreError> {
        use sqlx::Row as _;
        let marks = vec!["?"; roles.len()].join(", ");
        let text = format!(
            "/* mysql */ select count(*) as n from t_account_administration where gesture = ? and held_role in \
             ({marks}) and occurred_at >= ? and account_id <> ?"
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(text)).bind(gesture);
        for role in roles {
            query = query.bind(*role);
        }
        let n: i64 = query.bind(UtcInstant(since)).bind(excluding).fetch_one(pool).await?.try_get("n")?;
        Ok(n > 0)
    }

    pub(super) async fn count_other_admins(
        pool: &MySqlPool,
        roles: &[&str],
        excluding: i64,
    ) -> Result<i64, StoreError> {
        use sqlx::Row as _;
        let marks = vec!["?"; roles.len()].join(", ");
        let text = format!("/* mysql */ select count(*) as n from t_user where role in ({marks}) and id <> ?");
        let mut query = sqlx::query(sqlx::AssertSqlSafe(text));
        for role in roles {
            query = query.bind(*role);
        }
        Ok(query.bind(excluding).fetch_one(pool).await?.try_get("n")?)
    }

    pub(super) async fn record_gesture(
        connection: &mut MySqlConnection,
        account_id: i64,
        administrator_id: i64,
        gesture: &str,
        held_role: Option<&str>,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "/* mysql */ insert into t_account_administration (account_id, administrator_id, gesture, held_role, \
             occurred_at) values (?, ?, ?, ?, ?)",
            account_id,
            administrator_id,
            gesture,
            held_role,
            UtcInstant(at)
        )
        .execute(connection)
        .await?;
        Ok(())
    }

    pub(super) async fn account_named(pool: &MySqlPool, username: &str) -> Result<Option<(i64, String)>, StoreError> {
        let row = sqlx::query!("/* mysql */ select id, username from t_user where username = ?", username)
            .fetch_optional(pool)
            .await?;
        Ok(row.map(|row| (row.id, row.username)))
    }

    pub(super) async fn requests_in(pool: &MySqlPool, status: &str) -> Result<Vec<AccountRequest>, StoreError> {
        let rows = sqlx::query!(
            r#"/* mysql */ select id, kind, status, account_id, username, email, display_name, held_role,
               requested_role, password_hash, requested_by_id, requested_by,
               requested_at as "requested_at: UtcInstant", decided_by, decided_at as "decided_at: UtcInstant"
               from t_account_request where status = ? order by requested_at asc, id asc"#,
            status
        )
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|row| request_from!(row)).collect())
    }

    pub(super) async fn find_request(pool: &MySqlPool, id: i64) -> Result<Option<AccountRequest>, StoreError> {
        let row = sqlx::query!(
            r#"/* mysql */ select id, kind, status, account_id, username, email, display_name, held_role,
               requested_role, password_hash, requested_by_id, requested_by,
               requested_at as "requested_at: UtcInstant", decided_by, decided_at as "decided_at: UtcInstant"
               from t_account_request where id = ?"#,
            id
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| request_from!(row)))
    }

    pub(super) async fn lock_request(
        connection: &mut MySqlConnection,
        id: i64,
    ) -> Result<Option<AccountRequest>, StoreError> {
        let row = sqlx::query!(
            r#"/* mysql */ select id, kind, status, account_id, username, email, display_name, held_role,
               requested_role, password_hash, requested_by_id, requested_by,
               requested_at as "requested_at: UtcInstant", decided_by, decided_at as "decided_at: UtcInstant"
               from t_account_request where id = ? for update"#,
            id
        )
        .fetch_optional(connection)
        .await?;
        Ok(row.map(|row| request_from!(row)))
    }

    pub(super) async fn pending_for(pool: &MySqlPool, account_id: i64) -> Result<bool, StoreError> {
        let n: i64 = sqlx::query_scalar!(
            "/* mysql */ select count(*) from t_account_request where status = 'pending' and account_id = ?",
            account_id
        )
        .fetch_one(pool)
        .await?;
        Ok(n > 0)
    }

    pub(super) async fn pending_for_in(connection: &mut MySqlConnection, account_id: i64) -> Result<bool, StoreError> {
        let n: i64 = sqlx::query_scalar!(
            "/* mysql */ select count(*) from t_account_request where account_id = ? and status = 'pending'",
            account_id
        )
        .fetch_one(connection)
        .await?;
        Ok(n > 0)
    }

    pub(super) async fn creation_pending(connection: &mut MySqlConnection, username: &str) -> Result<bool, StoreError> {
        let n: i64 = sqlx::query_scalar!(
            "/* mysql */ select count(*) from t_account_request where status = 'pending' and kind = 'create' \
             and username = ?",
            username
        )
        .fetch_one(connection)
        .await?;
        Ok(n > 0)
    }

    pub(super) async fn lock_account(connection: &mut MySqlConnection, id: i64) -> Result<Option<String>, StoreError> {
        Ok(sqlx::query_scalar!("/* mysql */ select role from t_user where id = ? for update", id)
            .fetch_optional(connection)
            .await?)
    }

    pub(super) async fn insert_request(
        connection: &mut MySqlConnection,
        request: &NewAccountRequest,
    ) -> Result<i64, StoreError> {
        let done = sqlx::query!(
            "/* mysql */ insert into t_account_request (kind, status, account_id, username, email, display_name, \
             held_role, requested_role, password_hash, requested_by_id, requested_by, requested_at) \
             values (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            request.kind,
            request.account_id,
            request.username,
            request.email,
            request.display_name,
            request.held_role,
            request.requested_role,
            request.password_hash.as_ref().map(PasswordHash::encoded),
            request.requested_by_id,
            request.requested_by,
            UtcInstant(request.requested_at)
        )
        .execute(connection)
        .await?;
        i64::try_from(done.last_insert_id()).map_err(|error| StoreError(Box::new(error)))
    }

    pub(super) async fn decide(
        connection: &mut MySqlConnection,
        id: i64,
        status: &str,
        decided_by: &str,
        decided_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "/* mysql */ update t_account_request set status = ?, decided_by = ?, decided_at = ?, \
             password_hash = null where id = ?",
            status,
            decided_by,
            UtcInstant(decided_at),
            id
        )
        .execute(connection)
        .await?;
        Ok(())
    }
}

#[cfg(feature = "postgres-queries")]
mod postgres {
    use sqlx::{PgConnection, PgPool};
    use time::OffsetDateTime;
    use vectispire_cp_db::types::UtcInstant;

    use crate::persistence::model::{AccountRequest, NewAccountRequest, PasswordHash, StoreError};

    pub(super) async fn gestures_since(
        pool: &PgPool,
        account_id: i64,
        administrator_id: i64,
        since: OffsetDateTime,
    ) -> Result<Vec<String>, StoreError> {
        Ok(sqlx::query_scalar!(
            "/* postgres */ select gesture from t_account_administration where account_id = $1 \
             and administrator_id = $2 and occurred_at >= $3 order by occurred_at desc",
            account_id,
            administrator_id,
            since
        )
        .fetch_all(pool)
        .await?)
    }

    pub(super) async fn any_changed_from_since(
        pool: &PgPool,
        gesture: &str,
        roles: &[&str],
        since: OffsetDateTime,
        excluding: i64,
    ) -> Result<bool, StoreError> {
        let roles: Vec<String> = roles.iter().map(|role| (*role).to_owned()).collect();
        Ok(sqlx::query_scalar!(
            r#"/* postgres */ select exists(select 1 from t_account_administration where gesture = $1
               and held_role = any($2) and occurred_at >= $3 and account_id <> $4) as "any!""#,
            gesture,
            &roles,
            since,
            excluding
        )
        .fetch_one(pool)
        .await?)
    }

    pub(super) async fn count_other_admins(pool: &PgPool, roles: &[&str], excluding: i64) -> Result<i64, StoreError> {
        let roles: Vec<String> = roles.iter().map(|role| (*role).to_owned()).collect();
        Ok(sqlx::query_scalar!(
            r#"/* postgres */ select count(*) as "n!" from t_user where role = any($1) and id <> $2"#,
            &roles,
            excluding
        )
        .fetch_one(pool)
        .await?)
    }

    pub(super) async fn record_gesture(
        connection: &mut PgConnection,
        account_id: i64,
        administrator_id: i64,
        gesture: &str,
        held_role: Option<&str>,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "/* postgres */ insert into t_account_administration (account_id, administrator_id, gesture, held_role, \
             occurred_at) values ($1, $2, $3, $4, $5)",
            account_id,
            administrator_id,
            gesture,
            held_role,
            at
        )
        .execute(connection)
        .await?;
        Ok(())
    }

    pub(super) async fn account_named(pool: &PgPool, username: &str) -> Result<Option<(i64, String)>, StoreError> {
        let row = sqlx::query!("/* postgres */ select id, username from t_user where username = $1", username)
            .fetch_optional(pool)
            .await?;
        Ok(row.map(|row| (row.id, row.username)))
    }

    pub(super) async fn requests_in(pool: &PgPool, status: &str) -> Result<Vec<AccountRequest>, StoreError> {
        let rows = sqlx::query!(
            r#"/* postgres */ select id, kind, status, account_id, username, email, display_name, held_role,
               requested_role, password_hash, requested_by_id, requested_by,
               requested_at as "requested_at: UtcInstant", decided_by, decided_at as "decided_at: UtcInstant"
               from t_account_request where status = $1 order by requested_at asc, id asc"#,
            status
        )
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|row| request_from!(row)).collect())
    }

    pub(super) async fn find_request(pool: &PgPool, id: i64) -> Result<Option<AccountRequest>, StoreError> {
        let row = sqlx::query!(
            r#"/* postgres */ select id, kind, status, account_id, username, email, display_name, held_role,
               requested_role, password_hash, requested_by_id, requested_by,
               requested_at as "requested_at: UtcInstant", decided_by, decided_at as "decided_at: UtcInstant"
               from t_account_request where id = $1"#,
            id
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| request_from!(row)))
    }

    pub(super) async fn lock_request(
        connection: &mut PgConnection,
        id: i64,
    ) -> Result<Option<AccountRequest>, StoreError> {
        let row = sqlx::query!(
            r#"/* postgres */ select id, kind, status, account_id, username, email, display_name, held_role,
               requested_role, password_hash, requested_by_id, requested_by,
               requested_at as "requested_at: UtcInstant", decided_by, decided_at as "decided_at: UtcInstant"
               from t_account_request where id = $1 for update"#,
            id
        )
        .fetch_optional(connection)
        .await?;
        Ok(row.map(|row| request_from!(row)))
    }

    pub(super) async fn pending_for(pool: &PgPool, account_id: i64) -> Result<bool, StoreError> {
        Ok(sqlx::query_scalar!(
            r#"/* postgres */ select exists(select 1 from t_account_request where status = 'pending'
               and account_id = $1) as "pending!""#,
            account_id
        )
        .fetch_one(pool)
        .await?)
    }

    pub(super) async fn pending_for_in(connection: &mut PgConnection, account_id: i64) -> Result<bool, StoreError> {
        Ok(sqlx::query_scalar!(
            r#"/* postgres */ select exists(select 1 from t_account_request where account_id = $1
               and status = 'pending') as "pending!""#,
            account_id
        )
        .fetch_one(connection)
        .await?)
    }

    pub(super) async fn creation_pending(connection: &mut PgConnection, username: &str) -> Result<bool, StoreError> {
        Ok(sqlx::query_scalar!(
            r#"/* postgres */ select exists(select 1 from t_account_request where status = 'pending'
               and kind = 'create' and username = $1) as "pending!""#,
            username
        )
        .fetch_one(connection)
        .await?)
    }

    pub(super) async fn lock_account(connection: &mut PgConnection, id: i64) -> Result<Option<String>, StoreError> {
        Ok(sqlx::query_scalar!("/* postgres */ select role from t_user where id = $1 for update", id)
            .fetch_optional(connection)
            .await?)
    }

    pub(super) async fn insert_request(
        connection: &mut PgConnection,
        request: &NewAccountRequest,
    ) -> Result<i64, StoreError> {
        Ok(sqlx::query_scalar!(
            "/* postgres */ insert into t_account_request (kind, status, account_id, username, email, display_name, \
             held_role, requested_role, password_hash, requested_by_id, requested_by, requested_at) \
             values ($1, 'pending', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) returning id",
            request.kind,
            request.account_id,
            request.username,
            request.email,
            request.display_name,
            request.held_role,
            request.requested_role,
            request.password_hash.as_ref().map(PasswordHash::encoded),
            request.requested_by_id,
            request.requested_by,
            request.requested_at
        )
        .fetch_one(connection)
        .await?)
    }

    pub(super) async fn decide(
        connection: &mut PgConnection,
        id: i64,
        status: &str,
        decided_by: &str,
        decided_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "/* postgres */ update t_account_request set status = $1, decided_by = $2, decided_at = $3, \
             password_hash = null where id = $4",
            status,
            decided_by,
            decided_at,
            id
        )
        .execute(connection)
        .await?;
        Ok(())
    }
}

/// An engine this build was compiled without (`users.rs` says when).
#[cfg(any(not(feature = "mysql-queries"), not(feature = "postgres-queries")))]
mod unprepared {
    use time::OffsetDateTime;

    use crate::persistence::model::{AccountRequest, NewAccountRequest, StoreError};

    fn absent<T>() -> Result<T, StoreError> {
        Err(StoreError("this build has no statements for the engine".into()))
    }

    pub(super) async fn gestures_since<P>(_: &P, _: i64, _: i64, _: OffsetDateTime) -> Result<Vec<String>, StoreError> {
        absent()
    }
    pub(super) async fn any_changed_from_since<P>(
        _: &P,
        _: &str,
        _: &[&str],
        _: OffsetDateTime,
        _: i64,
    ) -> Result<bool, StoreError> {
        absent()
    }
    pub(super) async fn count_other_admins<P>(_: &P, _: &[&str], _: i64) -> Result<i64, StoreError> {
        absent()
    }
    pub(super) async fn record_gesture<C>(
        _: &mut C,
        _: i64,
        _: i64,
        _: &str,
        _: Option<&str>,
        _: OffsetDateTime,
    ) -> Result<(), StoreError> {
        absent()
    }
    pub(super) async fn account_named<P>(_: &P, _: &str) -> Result<Option<(i64, String)>, StoreError> {
        absent()
    }
    pub(super) async fn requests_in<P>(_: &P, _: &str) -> Result<Vec<AccountRequest>, StoreError> {
        absent()
    }
    pub(super) async fn find_request<P>(_: &P, _: i64) -> Result<Option<AccountRequest>, StoreError> {
        absent()
    }
    pub(super) async fn lock_request<C>(_: &mut C, _: i64) -> Result<Option<AccountRequest>, StoreError> {
        absent()
    }
    pub(super) async fn pending_for<P>(_: &P, _: i64) -> Result<bool, StoreError> {
        absent()
    }
    pub(super) async fn pending_for_in<C>(_: &mut C, _: i64) -> Result<bool, StoreError> {
        absent()
    }
    pub(super) async fn creation_pending<C>(_: &mut C, _: &str) -> Result<bool, StoreError> {
        absent()
    }
    pub(super) async fn lock_account<C>(_: &mut C, _: i64) -> Result<Option<String>, StoreError> {
        absent()
    }
    pub(super) async fn insert_request<C>(_: &mut C, _: &NewAccountRequest) -> Result<i64, StoreError> {
        absent()
    }
    pub(super) async fn decide<C>(_: &mut C, _: i64, _: &str, _: &str, _: OffsetDateTime) -> Result<(), StoreError> {
        absent()
    }
}

#[cfg(not(feature = "mysql-queries"))]
use unprepared as mysql;
#[cfg(not(feature = "postgres-queries"))]
use unprepared as postgres;

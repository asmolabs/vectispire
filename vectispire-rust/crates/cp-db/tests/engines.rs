//! The database layer against both engines, on a schema the real Flyway built from the repository's
//! migrations: the session, the column types, the transactions, the lock retry, the visibility, the
//! schema check. One test per engine, each running every check in turn on one server — a server per
//! check would multiply a two-minute start by twelve.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sea_query::{Alias, Expr, ExprTrait};
use support::Migrated;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::parity::{self, Column, ColumnType::*, Mismatch, MySqlText, Table, column, nullable};
use vectispire_cp_db::query::{Issues, Repositories};
use vectispire_cp_db::types::{TextUuid, UtcInstant, now};
use vectispire_cp_db::{
    Db, Engine, Mode, ScanTarget, Tx, Visibility, VisibleSelect, is_lock_conflict, retry_on_lock_conflict,
};

#[test]
fn on_mysql() {
    run(Engine::MySql);
}

#[test]
fn on_postgresql() {
    run(Engine::PostgreSql);
}

fn run(engine: Engine) {
    let database = Migrated::start(engine);
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let db = database.connect().await;
        assert_eq!(db.engine(), engine);
        the_session_is_the_java_drivers(&db).await;
        the_representative_tables_agree_with_the_schema(&db).await;
        a_disagreement_is_reported(&db).await;
        the_column_types_read_back_what_was_written(&db).await;
        a_read_only_transaction_refuses_a_write(&db).await;
        a_transaction_of_its_own_outlives_the_callers(&db).await;
        a_lock_the_engine_gives_up_on_is_retried(&db).await;
        a_reader_sees_only_the_targets_granted(&db).await;
        a_grant_of_seventy_thousand_targets_is_one_statement(&db).await;
        db.close().await;
    });
}

/// Each engine's placeholders: `?` for MySQL, `$n` for PostgreSQL — the tests write `?` and this
/// numbers them, which is sound only because no statement here holds a `?` in a literal.
fn sql(engine: Engine, text: &'static str) -> sqlx::AssertSqlSafe<String> {
    sqlx::AssertSqlSafe(match engine {
        Engine::MySql => text.to_owned(),
        Engine::PostgreSql => {
            let mut numbered = String::new();
            let mut n = 0;
            for character in text.chars() {
                if character == '?' {
                    n += 1;
                    numbered.push_str(&format!("${n}"));
                } else {
                    numbered.push(character);
                }
            }
            numbered
        }
    })
}

/// The same expression against whichever pool `db` holds — each arm type-checks on its own engine.
macro_rules! each {
    ($db:expr, $pool:ident => $body:expr) => {
        match $db {
            Db::MySql($pool) => $body,
            Db::PostgreSql($pool) => $body,
        }
    };
}

/// [`each!`] for a statement whose result differs per engine and is not needed.
macro_rules! each_do {
    ($db:expr, $pool:ident => $body:expr) => {
        match $db {
            Db::MySql($pool) => drop($body),
            Db::PostgreSql($pool) => drop($body),
        }
    };
}

async fn scalar_text(db: &Db, statement: &'static str) -> String {
    each!(db, pool => sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(statement)).fetch_one(pool).await.unwrap())
}

async fn the_session_is_the_java_drivers(db: &Db) {
    match db.engine() {
        Engine::MySql => {
            let session_mode = scalar_text(db, "select cast(@@session.sql_mode as char)").await;
            let global_mode = scalar_text(db, "select cast(@@global.sql_mode as char)").await;
            assert_eq!(session_mode, global_mode, "sqlx's PIPES_AS_CONCAT must not be appended");
            assert!(!session_mode.contains("PIPES_AS_CONCAT"));
            assert_eq!(scalar_text(db, "select cast(@@session.time_zone as char)").await, "+00:00");
            assert_eq!(
                scalar_text(db, "select cast(@@collation_connection as char)").await,
                scalar_text(db, "select cast(default_collate_name as char) from information_schema.character_sets where character_set_name = 'utf8mb4'").await,
                "the server's default collation, as Connector/J negotiates it"
            );
            assert_eq!(scalar_text(db, "select cast(@@transaction_isolation as char)").await, "REPEATABLE-READ");
        }
        Engine::PostgreSql => {
            assert_eq!(scalar_text(db, "show timezone").await, "UTC");
            assert_eq!(scalar_text(db, "show transaction_isolation").await, "read committed");
            assert_eq!(scalar_text(db, "show search_path").await, "\"$user\", public");
        }
    }
}

const USERS: &[Column] = &[
    column("id", Identity),
    column("username", Varchar(255)),
    nullable("email", Varchar(255)),
    nullable("password", Varchar(255)),
    column("role", Varchar(255)),
    column("is_active", Bool),
    column("created_at", Timestamp),
    column("updated_at", Timestamp),
    column("must_change_password", Bool),
    // `tinyint(1)` on MySQL, beside `bit(1)` in the same table: both are booleans.
    column("mfa_enabled", Bool),
    nullable("totp_secret", Text(MySqlText::Regular)),
    nullable("totp_last_step", BigInt),
];

const AUDIT_LOG: &[Column] = &[
    column("id", Char(36)),
    column("description", Varchar(255)),
    column("operation_type", Varchar(255)),
    column("resource_id", Varchar(255)),
    column("timestamp", Timestamp),
    nullable("user_id", Varchar(255)),
    nullable("ip_address", Varchar(64)),
    nullable("user_agent", Varchar(255)),
    nullable("previous_hash", Varchar(64)),
    nullable("entry_hash", Varchar(64)),
];

const CHECKLIST_FILES: &[Column] = &[
    column("id", Identity),
    column("project_id", BigInt),
    column("sha256", Varchar(64)),
    column("size_bytes", BigInt),
    column("content", Bytes),
];

const EPSS_SCORES: &[Column] = &[
    column("generation", BigInt),
    column("cve_id", Varchar(32)),
    column("score", Double),
    column("percentile", Double),
];

/// The engine-specific one: written before the placeholders, `timestamp` on MySQL (to the second) and
/// `timestamp without time zone` on PostgreSQL.
const SIEM_CONFIG: &[Column] = &[
    // Not generated: the configuration is one row, written with its id.
    column("id", BigInt),
    column("enabled", Bool),
    column("created_at", LegacyTimestamp { postgres_zoned: false }),
    column("updated_at", LegacyTimestamp { postgres_zoned: false }),
    nullable("tls_ca_pem", Text(MySqlText::Long)),
];

const ISSUES: &[Column] = &[
    column("id", Identity),
    nullable("repo_id", BigInt),
    nullable("container_id", BigInt),
    column("fingerprint", Varchar(64)),
    column("state", Varchar(20)),
    column("first_seen_at", Timestamp),
    column("is_kev", Bool),
    nullable("description", Text(MySqlText::Regular)),
];

const TABLES: &[Table] = &[
    Table { name: "t_user", columns: USERS },
    Table { name: "t_audit_log", columns: AUDIT_LOG },
    Table { name: "t_checklist_file", columns: CHECKLIST_FILES },
    Table { name: "t_epss_score", columns: EPSS_SCORES },
    Table { name: "t_siem_config", columns: SIEM_CONFIG },
    Table { name: "t_issue", columns: ISSUES },
];

async fn the_representative_tables_agree_with_the_schema(db: &Db) {
    if let Err(error) = parity::check(db, TABLES).await {
        panic!("{error}");
    }
}

async fn a_disagreement_is_reported(db: &Db) {
    const WRONG: &[Column] = &[
        column("id", Char(36)),
        column("username", Varchar(64)),
        column("email", Varchar(255)),
        column("not_there", Int),
        column("totp_secret", Text(MySqlText::Long)),
    ];
    let error =
        parity::check(db, &[Table { name: "t_user", columns: WRONG }, Table { name: "t_not_there", columns: &[] }])
            .await
            .unwrap_err();
    let parity::ParityError::Mismatches { mismatches, .. } = error else { panic!("{error}") };
    let expected_text_mismatch = db.engine() == Engine::MySql; // PostgreSQL has one text type
    assert!(matches!(mismatches[0], Mismatch::Type { column: "id", .. }), "{mismatches:?}");
    assert!(matches!(mismatches[1], Mismatch::Type { column: "username", .. }), "{mismatches:?}");
    assert!(
        matches!(mismatches[2], Mismatch::Nullability { column: "email", declared_nullable: false, .. }),
        "{mismatches:?}"
    );
    assert!(matches!(mismatches[3], Mismatch::MissingColumn { column: "not_there", .. }), "{mismatches:?}");
    let rest = &mismatches[4..];
    assert_eq!(
        rest.iter().filter(|m| matches!(m, Mismatch::Type { column: "totp_secret", .. })).count(),
        usize::from(expected_text_mismatch)
    );
    assert!(matches!(rest.last(), Some(Mismatch::MissingTable { table: "t_not_there" })), "{mismatches:?}");
}

async fn the_column_types_read_back_what_was_written(db: &Db) {
    let engine = db.engine();

    // char(36) ids and datetime(6): an audit entry.
    let id = TextUuid(Uuid::from_u128(u128::from(std::process::id()) << 64 | 0x4000_8000_0000_0001));
    let at = OffsetDateTime::from_unix_timestamp_nanos(1_760_000_000_123_456_789).unwrap();
    let stored = vectispire_cp_db::types::to_microseconds(at);
    each_do!(db, pool => sqlx::query(sql(engine, "insert into t_audit_log (id, description, operation_type, resource_id, timestamp) values (?, 'd', 'TEST', 'r', ?)"))
        .bind(id).bind(stored).execute(pool).await.unwrap());
    let (read_id, read_at): (TextUuid, OffsetDateTime) = each!(db, pool => sqlx::query_as(sql(engine, "select id, timestamp from t_audit_log where id = ?")).bind(id).fetch_one(pool).await.unwrap());
    assert_eq!((read_id, read_at), (id, stored));
    let text: String = each!(db, pool => sqlx::query_scalar(sql(engine, "select cast(id as char(36)) from t_audit_log where id = ?")).bind(id).fetch_one(pool).await.unwrap());
    assert_eq!(text, id.0.as_hyphenated().to_string(), "the hyphenated lower-case text Hibernate writes");
    assert_eq!(now().nanosecond() % 1_000, 0);

    // bit(1) and tinyint(1) side by side.
    let instant = now();
    each_do!(db, pool => sqlx::query(sql(engine, "insert into t_user (username, role, is_active, created_at, updated_at, must_change_password, mfa_enabled) values ('types', 'USER', ?, ?, ?, ?, ?)"))
        .bind(true).bind(instant).bind(instant).bind(false).bind(true).execute(pool).await.unwrap());
    let flags: (bool, bool, bool) = each!(db, pool => sqlx::query_as("select is_active, must_change_password, mfa_enabled from t_user where username = 'types'").fetch_one(pool).await.unwrap());
    assert_eq!(flags, (true, false, true));

    // longblob / bytea, every byte value.
    let bytes: Vec<u8> = (0..=255).collect();
    each_do!(db, pool => sqlx::query(sql(engine, "insert into t_checklist_file (project_id, sha256, size_bytes, content) values (1, 'x', 256, ?)"))
        .bind(&bytes).execute(pool).await.unwrap());
    let read: Vec<u8> = each!(db, pool => sqlx::query_scalar("select content from t_checklist_file where sha256 = 'x'").fetch_one(pool).await.unwrap());
    assert_eq!(read, bytes);

    // double / double precision, to the bit.
    let score = 0.1_f64 + 0.2_f64;
    each_do!(db, pool => sqlx::query(sql(engine, "insert into t_epss_score (generation, cve_id, score, percentile) values (1, 'CVE-0000-0001', ?, ?)"))
        .bind(score).bind(f64::MIN_POSITIVE).execute(pool).await.unwrap());
    let read: (f64, f64) = each!(db, pool => sqlx::query_as("select score, percentile from t_epss_score where cve_id = 'CVE-0000-0001'").fetch_one(pool).await.unwrap());
    assert_eq!((read.0.to_bits(), read.1.to_bits()), (score.to_bits(), f64::MIN_POSITIVE.to_bits()));

    // The legacy timestamps: to the second on MySQL, which rounds the fraction away as it does for the
    // Java side; kept on PostgreSQL, read from a column without a zone as the UTC it holds.
    let written = OffsetDateTime::from_unix_timestamp_nanos(1_760_000_000_400_000_000).unwrap();
    each_do!(db, pool => sqlx::query(sql(engine, "insert into t_siem_config (id, enabled, created_at, updated_at) values (99, ?, ?, ?)"))
        .bind(false).bind(UtcInstant(written)).bind(UtcInstant(written)).execute(pool).await.unwrap());
    let read: UtcInstant = each!(db, pool => sqlx::query_scalar("select created_at from t_siem_config where id = 99").fetch_one(pool).await.unwrap());
    match engine {
        Engine::MySql => assert_eq!(read.0.unix_timestamp_nanos(), 1_760_000_000_000_000_000),
        Engine::PostgreSql => assert_eq!(read.0, written),
    }
}

async fn a_read_only_transaction_refuses_a_write(db: &Db) {
    let mut tx = db.begin(Mode::ReadOnly).await.unwrap();
    let statement =
        "insert into t_epss_score (generation, cve_id, score, percentile) values (2, 'CVE-0000-0002', 0, 0)";
    let refusal = match &mut tx {
        Tx::MySql(tx) => sqlx::query(statement).execute(&mut **tx).await.unwrap_err(),
        Tx::PostgreSql(tx) => sqlx::query(statement).execute(&mut **tx).await.unwrap_err(),
    };
    let sqlx::Error::Database(database) = &refusal else { panic!("{refusal}") };
    match db.engine() {
        // ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
        Engine::MySql => assert_eq!(database.code().as_deref(), Some("25006"), "{refusal}"),
        // read_only_sql_transaction
        Engine::PostgreSql => assert_eq!(database.code().as_deref(), Some("25006"), "{refusal}"),
    }
    tx.rollback().await.unwrap();
    // A read in a read-only transaction works, of course.
    let mut tx = db.begin(Mode::ReadOnly).await.unwrap();
    let count: i64 = match &mut tx {
        Tx::MySql(tx) => sqlx::query_scalar("select count(*) from t_epss_score").fetch_one(&mut **tx).await.unwrap(),
        Tx::PostgreSql(tx) => {
            sqlx::query_scalar("select count(*) from t_epss_score").fetch_one(&mut **tx).await.unwrap()
        }
    };
    assert!(count >= 1);
    tx.commit().await.unwrap();
}

async fn insert_score(tx: &mut Tx, cve: &'static str) {
    let engine = tx.engine();
    match tx {
        Tx::MySql(tx) => drop(
            sqlx::query(sql(
                engine,
                "insert into t_epss_score (generation, cve_id, score, percentile) values (3, ?, 0, 0)",
            ))
            .bind(cve)
            .execute(&mut **tx)
            .await
            .unwrap(),
        ),
        Tx::PostgreSql(tx) => drop(
            sqlx::query(sql(
                engine,
                "insert into t_epss_score (generation, cve_id, score, percentile) values (3, ?, 0, 0)",
            ))
            .bind(cve)
            .execute(&mut **tx)
            .await
            .unwrap(),
        ),
    }
}

async fn a_transaction_of_its_own_outlives_the_callers(db: &Db) {
    let mut caller = db.begin(Mode::ReadWrite).await.unwrap();
    insert_score(&mut caller, "CVE-CALLER").await;
    // REQUIRES_NEW: a second transaction, on a second connection, committed while the first is open.
    let mut own = db.begin(Mode::ReadWrite).await.unwrap();
    insert_score(&mut own, "CVE-OWN").await;
    own.commit().await.unwrap();
    caller.rollback().await.unwrap();
    let kept: Vec<String> = each!(db, pool => sqlx::query_scalar("select cve_id from t_epss_score where generation = 3 order by cve_id").fetch_all(pool).await.unwrap());
    assert_eq!(kept, ["CVE-OWN"]);
}

/// Takes `t_audit_chain_head`'s row in `tx`, with a short lock wait — the lock the audit log serialises on.
async fn lock_chain_head(tx: &mut Tx) -> Result<(), sqlx::Error> {
    match tx {
        Tx::MySql(tx) => {
            // The engine's minimum: one second.
            sqlx::query("set session innodb_lock_wait_timeout = 1").execute(&mut **tx).await?;
            sqlx::query("select id from t_audit_chain_head for update").fetch_all(&mut **tx).await?;
        }
        Tx::PostgreSql(tx) => {
            sqlx::query("set local lock_timeout = '200ms'").execute(&mut **tx).await?;
            sqlx::query("select id from t_audit_chain_head for update").fetch_all(&mut **tx).await?;
        }
    }
    Ok(())
}

async fn a_lock_the_engine_gives_up_on_is_retried(db: &Db) {
    let mut holder = db.begin(Mode::ReadWrite).await.unwrap();
    lock_chain_head(&mut holder).await.unwrap();

    // Refused while held, and recognised as a lock conflict rather than as a broken statement.
    let mut waiter = db.begin(Mode::ReadWrite).await.unwrap();
    let refusal = lock_chain_head(&mut waiter).await.unwrap_err();
    assert!(is_lock_conflict(&refusal), "{refusal}");
    waiter.rollback().await.unwrap();
    let broken = each!(db, pool => sqlx::query("select no_such_column from t_audit_chain_head").fetch_all(pool).await.unwrap_err());
    assert!(!is_lock_conflict(&broken), "a statement that is wrong is not retried: {broken}");

    // Retried until the holder lets go.
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        holder.commit().await.unwrap();
    });
    let attempts = AtomicU32::new(0);
    retry_on_lock_conflict(&vectispire_cp_db::LOCK_BACKOFF, || async {
        attempts.fetch_add(1, Ordering::Relaxed);
        let mut tx = db.begin(Mode::ReadWrite).await?;
        lock_chain_head(&mut tx).await?;
        tx.commit().await
    })
    .await
    .unwrap();
    release.await.unwrap();
    assert!(attempts.load(Ordering::Relaxed) >= 2, "the first attempt waited on the holder and was retried");
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct Row {
    id: i64,
    fingerprint: String,
}

async fn a_reader_sees_only_the_targets_granted(db: &Db) {
    let engine = db.engine();
    let mut ids = Vec::new();
    for url in ["https://r1.example.org/a.git", "https://r2.example.org/b.git"] {
        each_do!(db, pool => sqlx::query(sql(engine, "insert into t_repository (url, branch) values (?, 'main')")).bind(url).execute(pool).await.unwrap());
        let id: i64 = each!(db, pool => sqlx::query_scalar(sql(engine, "select id from t_repository where url = ?")).bind(url).fetch_one(pool).await.unwrap());
        ids.push(id);
    }
    let (r1, r2) = (ids[0], ids[1]);
    let mut images = Vec::new();
    for name in ["c1", "c2"] {
        each_do!(db, pool => sqlx::query(sql(engine, "insert into t_container (image_name, tag) values (?, 'latest')")).bind(name).execute(pool).await.unwrap());
        let id: i64 = each!(db, pool => sqlx::query_scalar(sql(engine, "select id from t_container where image_name = ?")).bind(name).fetch_one(pool).await.unwrap());
        images.push(id);
    }
    let (c1, c2) = (images[0], images[1]);
    let instant = now();
    for (fingerprint, repo, container) in [
        ("of-r1", Some(r1), None),
        ("of-r2", Some(r2), None),
        ("of-c1", None, Some(c1)),
        ("of-r1-and-c2", Some(r1), Some(c2)),
    ] {
        each_do!(db, pool => sqlx::query(sql(engine,
            "insert into t_issue (repo_id, container_id, fingerprint, type, state, first_seen_at, last_seen_at, times_seen, triage_status, reachability, revision, is_kev) \
             values (?, ?, ?, 'vulnerability', 'open', ?, ?, 1, 'untriaged', 'unknown', 0, ?)"))
            .bind(repo).bind(container).bind(fingerprint).bind(instant).bind(instant).bind(false).execute(pool).await.unwrap());
    }

    let fingerprints = |visibility: Visibility| async move {
        let rows: Vec<Row> = VisibleSelect::<Issues>::columns(&visibility, &["id", "fingerprint"])
            .order_by("fingerprint", sea_query::Order::Asc)
            .fetch_all(db)
            .await
            .unwrap();
        rows.into_iter().map(|row| row.fingerprint).collect::<Vec<_>>()
    };
    use ScanTarget::{Container, Repository};
    assert_eq!(fingerprints(Visibility::everything()).await, ["of-c1", "of-r1", "of-r1-and-c2", "of-r2"]);
    assert_eq!(fingerprints(Visibility::only([Repository(r1)])).await, ["of-r1", "of-r1-and-c2"]);
    // A row naming both a repository and an image is the repository's: the image's reader does not see it.
    assert_eq!(fingerprints(Visibility::only([Container(c2)])).await, Vec::<String>::new());
    assert_eq!(fingerprints(Visibility::only([Container(c1), Repository(r2)])).await, ["of-c1", "of-r2"]);
    assert_eq!(fingerprints(Visibility::only([])).await, Vec::<String>::new());

    let open_of_r1 = VisibleSelect::<Issues>::count(&Visibility::only([Repository(r1)]))
        .and_where(Expr::col(Alias::new("state")).eq("open"))
        .fetch_count(db)
        .await
        .unwrap();
    assert_eq!(open_of_r1, 2);
    assert_eq!(
        VisibleSelect::<Repositories>::count(&Visibility::only([Container(c1)])).fetch_count(db).await.unwrap(),
        0
    );
}

async fn a_grant_of_seventy_thousand_targets_is_one_statement(db: &Db) {
    // Past PostgreSQL's 65,535 bound parameters, which a page of a project's backlog once exceeded.
    let first: i64 =
        each!(db, pool => sqlx::query_scalar("select min(id) from t_repository").fetch_one(pool).await.unwrap());
    let visibility = Visibility::only((first..first + 70_000).map(ScanTarget::Repository));
    let visible = VisibleSelect::<Repositories>::count(&visibility).fetch_count(db).await.unwrap();
    assert_eq!(visible, 2);
}

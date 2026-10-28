//! The access module's statements on both engines, against the schema `vectispire-migrate` builds from the Java
//! tree's migrations — and the whole Java matrix (`reference/access/allowances.json`) run through them.
//!
//! For each engine: a database of its own (`vectispire_cp_db::testing`'s, removed when the test ends; a missing
//! Docker fails the test), the migrations, the matrix's accounts, teams, grants, projects, targets and backlog seeded as rows, then
//! for every case the real [`VisibilityService`] — its read-only transaction and its two statements (the direct
//! grants, and the teams' through a join) — and a real [`VisibleSelect`] on `t_issue` with the allowance it produced. Both must equal
//! what the Java side answered for the same accounts. Then [`TriageApprovers`] counts on the same rows.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::print_stdout)]

#[path = "authz_support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::AssertSqlSafe;
use std::net::SocketAddr;
use support::{allowance, reference, visibility};
use tower::ServiceExt;
use vectispire_cp_access::TriageApprovers;
use vectispire_cp_access::four_eyes::SwitchOnRefusal;
use vectispire_cp_access::security::{CallerScope, CallerVisibility, PrincipalDirectory};
use vectispire_cp_access::visibility::{
    AccessError, AccessSettings, AccountRef, Allowance, GrantableTargets, VisibilityService,
};
use vectispire_cp_db::Visibility;
use vectispire_cp_db::query::Issues;
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, ScanTarget, VisibleSelect};
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{BoxFuture, RecordingAudit, StaticCredentials};
use vectispire_cp_http::extract::Scoped;
use vectispire_cp_http::principal::{Account, ApiKeyScope, Credential, Principal, Role};
use vectispire_cp_http::routes::{Route, Routes, VisibilityOf};
use vectispire_cp_http::{Access, Problem};
use vectispire_migrate::{Database, Engine, Options};

/// A database of its own, `vectispire_cp_db::testing`'s: in a throwaway container, or on the shared server
/// `VECTISPIRE_TEST_MYSQL_URL` / `VECTISPIRE_TEST_POSTGRES_URL` names.
struct Server {
    engine: Engine,
    database: TestDatabase,
}

impl Server {
    fn start(engine: Engine) -> Server {
        let database = TestDatabase::empty(match engine {
            Engine::MySql => vectispire_cp_db::Engine::MySql,
            Engine::PostgreSql => vectispire_cp_db::Engine::PostgreSql,
        });
        Server { engine, database }
    }

    fn url(&self) -> String {
        self.database.url()
    }

    /// The migration runner's pools, once a query has succeeded twice a second apart: the images' entrypoints
    /// restart the server once while initialising.
    async fn database(&self) -> Database {
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut successes = 0;
        loop {
            let attempt = match self.engine {
                Engine::MySql => sqlx::mysql::MySqlPoolOptions::new()
                    .max_connections(4)
                    .connect(&self.url())
                    .await
                    .map(Database::MySql),
                Engine::PostgreSql => sqlx::postgres::PgPoolOptions::new()
                    .max_connections(4)
                    .connect(&self.url())
                    .await
                    .map(Database::PostgreSql),
            };
            match attempt {
                Ok(database) if execute_ok(&database, "SELECT 1").await => {
                    successes += 1;
                    if successes == 2 {
                        return database;
                    }
                }
                _ => successes = 0,
            }
            assert!(Instant::now() < deadline, "{:?} never answered", self.engine);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// The control plane's own pool, opened from the `jdbc:` URL as a deployment writes it.
    async fn db(&self) -> Db {
        let mut settings = self.database.settings.clone();
        settings.pool.max_connections = 4;
        Db::connect(&settings).await.unwrap()
    }
}

async fn execute_ok(database: &Database, sql: &str) -> bool {
    let sql = AssertSqlSafe(sql.to_owned());
    match database {
        Database::MySql(pool) => sqlx::raw_sql(sql).execute(pool).await.is_ok(),
        Database::PostgreSql(pool) => sqlx::raw_sql(sql).execute(pool).await.is_ok(),
    }
}

/// Runs the test's own literal statements, failing on the first refused one.
async fn execute(database: &Database, statements: &[String]) {
    for statement in statements {
        let sql = AssertSqlSafe(statement.clone());
        let result = match database {
            Database::MySql(pool) => sqlx::raw_sql(sql).execute(pool).await.map(drop),
            Database::PostgreSql(pool) => sqlx::raw_sql(sql).execute(pool).await.map(drop),
        };
        result.unwrap_or_else(|error| panic!("{statement}: {error}"));
    }
}

/// The settings store, answering the matrix case's stored value.
struct StoredMode(String);

impl AccessSettings for StoredMode {
    fn target_visibility(&self) -> BoxFuture<'_, Result<String, AccessError>> {
        Box::pin(async move { Ok(self.0.clone()) })
    }
}

/// `GrantableTargets.targetsIn` as the targets module answers it: the repositories and images whose `project_id`
/// is one of these.
struct FiledTargets(Db);

impl GrantableTargets for FiledTargets {
    fn targets_in<'a>(&'a self, projects: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<Vec<ScanTarget>, AccessError>> {
        Box::pin(async move {
            let list = projects.iter().map(i64::to_string).collect::<Vec<_>>().join(", ");
            let repositories = format!("select id from t_repository where project_id in ({list}) order by id");
            let containers = format!("select id from t_container where project_id in ({list}) order by id");
            let ids = |sql: String| async {
                let sql = AssertSqlSafe(sql);
                match &self.0 {
                    Db::MySql(pool) => sqlx::query_scalar::<_, i64>(sql).fetch_all(pool).await,
                    Db::PostgreSql(pool) => sqlx::query_scalar::<_, i64>(sql).fetch_all(pool).await,
                }
                .map_err(|failure| AccessError::Port(failure.to_string()))
            };
            let mut targets: Vec<ScanTarget> =
                ids(repositories).await?.into_iter().map(ScanTarget::Repository).collect();
            targets.extend(ids(containers).await?.into_iter().map(ScanTarget::Container));
            Ok(targets)
        })
    }
}

/// The matrix's rows. Ids are the Java run's, so a case names the same account on both sides.
fn seed(engine: Engine, file: &Value) -> Vec<String> {
    let (now, active, no) = match engine {
        Engine::MySql => ("now(6)", "b'1'", "b'0'"),
        Engine::PostgreSql => ("now()", "true", "false"),
    };
    // PostgreSQL refuses an explicit id in an identity column `generated always` unless told it is meant.
    let overriding = match engine {
        Engine::MySql => "",
        Engine::PostgreSql => " overriding system value",
    };
    let mut sql =
        vec![format!("insert into t_solution (id, name, created_at){overriding} values (1, 'Retail', {now})")];
    let projects = file["projects"].as_object().unwrap();
    let mut filed_repositories = std::collections::BTreeMap::new();
    let mut filed_containers = std::collections::BTreeMap::new();
    for (project, targets) in projects {
        sql.push(format!(
            "insert into t_project (id, solution_id, name, created_at){overriding} values ({project}, 1, 'project {project}', {now})"
        ));
        for target in targets.as_array().unwrap() {
            if let Some(id) = target.get("repository") {
                filed_repositories.insert(id.as_i64().unwrap(), project.clone());
            } else {
                filed_containers.insert(target["container"].as_i64().unwrap(), project.clone());
            }
        }
    }
    for id in [101, 102, 103, 104, 105, 106, 999] {
        let project = filed_repositories.get(&id).cloned().unwrap_or_else(|| "null".into());
        sql.push(format!(
            "insert into t_repository (id, url, branch, project_id){overriding} values ({id}, 'https://forge.example/r{id}.git', 'main', {project})"
        ));
    }
    for id in [201, 202, 203, 204, 205] {
        let project = filed_containers.get(&id).cloned().unwrap_or_else(|| "null".into());
        sql.push(format!(
            "insert into t_container (id, image_name, tag, project_id){overriding} values ({id}, 'registry.example/i{id}', 'v1', {project})"
        ));
    }
    let mut accounts = BTreeSet::new();
    for case in file["cases"].as_array().unwrap() {
        if let (Some(id), Some(role)) = (case["userId"].as_i64(), case["role"].as_str()) {
            accounts.insert((id, role.to_owned(), case["setup"].as_str().unwrap().to_owned()));
        }
    }
    for (id, role, _) in &accounts {
        sql.push(format!(
            "insert into t_user (id, username, role, is_active, created_at, updated_at, must_change_password){overriding} \
             values ({id}, 'u{id}', '{role}', {active}, {now}, {now}, {no})"
        ));
    }
    for setup in file["setups"].as_array().unwrap() {
        let name = setup["name"].as_str().unwrap();
        let members: Vec<i64> = accounts.iter().filter(|(_, _, of)| of == name).map(|(id, _, _)| *id).collect();
        for team in setup["teams"].as_array().unwrap() {
            let team_id = team["id"].as_i64().unwrap();
            sql.push(format!(
                "insert into t_team (id, name, created_at){overriding} values ({team_id}, 'team {team_id}', {now})"
            ));
            for member in &members {
                sql.push(format!("insert into t_team_member (team_id, user_id) values ({team_id}, {member})"));
            }
            for grant in team["grants"].as_array().unwrap() {
                sql.push(format!(
                    "insert into t_team_target (team_id, target_kind, target_id) values ({team_id}, '{}', {})",
                    grant[0].as_str().unwrap(),
                    grant[1]
                ));
            }
        }
        for member in &members {
            for grant in setup["direct"].as_array().unwrap() {
                sql.push(format!(
                    "insert into t_user_target (user_id, target_kind, target_id) values ({member}, '{}', {})",
                    grant[0].as_str().unwrap(),
                    grant[1]
                ));
            }
        }
    }
    for issue in file["issues"].as_array().unwrap() {
        let column = |key: &str| if issue[key].is_null() { "null".to_owned() } else { issue[key].to_string() };
        sql.push(format!(
            "insert into t_issue (id, fingerprint, type, first_seen_at, last_seen_at, repo_id, container_id){overriding} \
             values ({}, 'fp-{}', 'vulnerability', {now}, {now}, {}, {})",
            issue["id"],
            issue["id"],
            column("repoId"),
            column("containerId")
        ));
    }
    sql
}

async fn the_matrix_on(engine: Engine) {
    let file = reference("allowances.json");
    let server = Server::start(engine);
    let database = server.database().await;
    let report = vectispire_migrate::run(&database, &Options::default()).await.unwrap();
    assert!(report.applied.len() > 80, "the migrations ran: {} applied", report.applied.len());
    execute(&database, &seed(engine, &file)).await;

    let db = server.db().await;
    let targets: Arc<dyn GrantableTargets> = Arc::new(FiledTargets(db.clone()));
    let mut checked = 0;
    for case in file["cases"].as_array().unwrap() {
        let service = VisibilityService::new(
            db.clone(),
            Arc::new(StoredMode(case["mode"].as_str().unwrap().to_owned())),
            targets.clone(),
        );
        let account =
            case["userId"].as_i64().map(|id| AccountRef { id, role: case["role"].as_str().unwrap().to_owned() });
        let restriction = visibility(&case["restriction"]);
        let got = service.allowance(account.as_ref(), &restriction).await.unwrap();
        assert_eq!(got, allowance(&case["allowance"]), "{engine:?}: {case}");
        assert_eq!(service.of(account.as_ref(), &restriction).await.unwrap(), got.visibility, "{engine:?}: {case}");

        let rows: Vec<(i64,)> = VisibleSelect::<Issues>::columns(&got.visibility, &["id"])
            .order_by("id", sea_query::Order::Asc)
            .fetch_all(&db)
            .await
            .unwrap();
        let ids: Vec<i64> = rows.into_iter().map(|(id,)| id).collect();
        let expected: Vec<i64> =
            case["visibleIssues"].as_array().unwrap().iter().map(|id| id.as_i64().unwrap()).collect();
        assert_eq!(ids, expected, "{engine:?}: the backlog this allowance reads: {case}");
        checked += 1;
    }
    assert_eq!(checked, file["cases"].as_array().unwrap().len());
    println!("{engine:?}: {checked} cases, each through the grants' statements and a visible select");

    the_route_hands_the_allowance_to_the_query(&db, &file).await;
    the_approvers_on(&database, &db).await;
}

/// Who a principal is, as the credentials module will answer it: the matrix's accounts by user name, a session
/// unrestricted, the integration key narrowed to repository 101 — and one account whose lookup fails.
struct Directory;

const FAILING: &str = "u-unanswerable";

impl PrincipalDirectory for Directory {
    fn account<'a>(&'a self, principal: &'a Principal) -> BoxFuture<'a, Result<Option<AccountRef>, AccessError>> {
        Box::pin(async move {
            let Some(account) = &principal.account else { return Ok(None) };
            if account.username == FAILING {
                return Err(AccessError::Port("the accounts table did not answer".into()));
            }
            let id = account.username.trim_start_matches('u').parse().unwrap();
            Ok(Some(AccountRef { id, role: "USER".into() }))
        })
    }

    fn restriction<'a>(&'a self, principal: &'a Principal) -> BoxFuture<'a, Result<Visibility, AccessError>> {
        Box::pin(async move {
            Ok(match principal.credential {
                Credential::Integration { .. } => Visibility::only([ScanTarget::Repository(101)]),
                _ => Visibility::everything(),
            })
        })
    }
}

/// A `.scoped()` route of the real chain, its allowance resolved by [`CallerVisibility`] before the handler runs,
/// and the handler's query narrowed by it: the backlog a session, a narrowed key, an agent and a failed lookup read.
async fn the_route_hands_the_allowance_to_the_query(db: &Db, file: &Value) {
    let service =
        VisibilityService::new(db.clone(), Arc::new(StoredMode("assigned".into())), Arc::new(FiledTargets(db.clone())));
    let reader = db.clone();
    let issues = move |Scoped(scope): Scoped<CallerScope>| {
        let db = reader.clone();
        async move {
            let allowance =
                scope.map_err(|_| Problem::handler(http::StatusCode::INTERNAL_SERVER_ERROR, "unavailable"))?;
            let rows: Vec<(i64,)> = VisibleSelect::<Issues>::columns(&allowance.visibility, &["id"])
                .order_by("id", sea_query::Order::Asc)
                .fetch_all(&db)
                .await
                .unwrap();
            Ok::<_, Problem>(rows.into_iter().map(|(id,)| id.to_string()).collect::<Vec<_>>().join(","))
        }
    };
    let routes = Routes::new(CallerVisibility::new(service, Arc::new(Directory))).route(
        Route::get("/api/v1/_probe/issues")
            .requires(Access::Account)
            .scoped()
            .accepts_api_key(ApiKeyScope::Read)
            .handler(issues),
    );
    // The account of setup "direct-project" with the role USER: project 10 granted to it directly.
    let user = file["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["setup"] == "direct-project" && case["role"] == "USER")
        .unwrap()["userId"]
        .as_i64()
        .unwrap();
    let account = |name: String| Account { username: name, role: Some(Role::User), must_change_password: false };
    let credentials = StaticCredentials::default()
        .session("tok-reader", Principal::session(account(format!("u{user}"))))
        .session("tok-failing", Principal::session(account(FAILING.into())))
        .key("zsk_narrow", Principal::integration(account(format!("u{user}")), "key-1", vec![ApiKeyScope::Read]));
    let chain =
        Arc::new(Chain::new(ChainConfig::default(), Arc::new(credentials), Arc::new(RecordingAudit::default())));
    let router = routes.build(&chain, None).unwrap();

    let expected = |restriction: Value| -> String {
        let case = file["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["userId"] == user && case["mode"] == "assigned" && case["restriction"] == restriction)
            .unwrap();
        case["visibleIssues"].as_array().unwrap().iter().map(|id| id.to_string()).collect::<Vec<_>>().join(",")
    };
    let get = |token: &str| {
        let mut request = http::Request::builder()
            .uri("/api/v1/_probe/issues")
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo("203.0.113.9:40000".parse::<SocketAddr>().unwrap()));
        router.clone().oneshot(request)
    };
    let body = |response: http::Response<axum::body::Body>| async move {
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    };

    let (status, ids) = body(get("tok-reader").await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(ids, expected(serde_json::json!("everything")), "a session reads what the account was granted");
    let (status, ids) = body(get("zsk_narrow").await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(
        ids,
        expected(serde_json::json!({ "only": [{ "repository": 101 }] })),
        "a narrowed key reads its target only"
    );
    let (status, _) = body(get("tok-failing").await.unwrap()).await;
    assert_eq!(status, 500, "a lookup that failed is an error, never an empty backlog");

    // The two principals no account stands behind: an agent sees everything (it reads no backlog), the SCIM client
    // nothing — `VisibilityService.of(AgentView)` and `resolve(null)`.
    let caller = CallerVisibility::new(
        VisibilityService::new(db.clone(), Arc::new(StoredMode("assigned".into())), Arc::new(FiledTargets(db.clone()))),
        Arc::new(Directory),
    );
    assert_eq!(caller.of(&Principal::agent("agent-1")).await, Ok(Allowance::everything()));
    assert_eq!(caller.of(&Principal::scim()).await, Ok(Allowance::nothing()));
}

/// `TriageApprovers` on the matrix's accounts, then with accounts deactivated: the count is of **active** accounts
/// holding a role that may approve (or publish), and the roles are the Java lists.
async fn the_approvers_on(database: &Database, db: &Db) {
    let roles = reference("roles.json");
    let list = |key: &str| -> Vec<String> {
        roles[key].as_array().unwrap().iter().map(|role| format!("'{}'", role.as_str().unwrap())).collect()
    };
    let approvers = list("approverRoles").join(", ");
    let publishers = list("publisherRoles").join(", ");
    let approvals = TriageApprovers::new(db.clone());
    assert!(approvals.any_active().await.unwrap());
    assert!(approvals.two_can_publish_templates().await.unwrap());
    assert!(approvals.two_can_sign_off_checklists().await.unwrap());
    assert_eq!(approvals.refusal_to_switch_on("true").await.unwrap(), None);

    let (active, inactive) = match database {
        Database::MySql(_) => ("b'1'", "b'0'"),
        Database::PostgreSql(_) => ("true", "false"),
    };
    // Exactly two active approvers: the boundary — two may sign a checklist off, and four-eyes may be switched on.
    execute(
        database,
        &[format!("update t_user set is_active = {inactive} where role in ({approvers}) and id not in (select id from (select id from t_user where role in ({approvers}) order by id limit 2) lowest)")],
    )
    .await;
    assert!(approvals.two_can_sign_off_checklists().await.unwrap(), "two approvers are two");
    assert_eq!(approvals.refusal_to_switch_on("true").await.unwrap(), None);
    // One active approver left: some approver at all, but not two to sign a checklist off.
    execute(
        database,
        &[format!("update t_user set is_active = {inactive} where role in ({approvers}) and id <> (select id from (select min(id) as id from t_user where role in ({approvers})) lowest)")],
    )
    .await;
    assert!(approvals.any_active().await.unwrap());
    assert!(!approvals.two_can_sign_off_checklists().await.unwrap());
    assert_eq!(approvals.refusal_to_switch_on(" true ").await.unwrap(), Some(SwitchOnRefusal::OneSignatory));
    // None: four-eyes would put every decision in a queue nobody can empty.
    execute(database, &[format!("update t_user set is_active = {inactive} where role in ({approvers})")]).await;
    assert!(!approvals.any_active().await.unwrap());
    assert_eq!(approvals.refusal_to_switch_on("1").await.unwrap(), Some(SwitchOnRefusal::NoApprover));
    // Switching off is never refused, whoever is left.
    assert_eq!(approvals.refusal_to_switch_on("false").await.unwrap(), None);
    // Publishers: SUPERUSER is one and approves nothing; with every approver gone, the governors still publish.
    let governors_publish = approvals.two_can_publish_templates().await.unwrap();
    assert!(governors_publish, "the platform governors are two active publishers");
    execute(database, &[format!("update t_user set is_active = {inactive} where role in ({publishers})")]).await;
    assert!(!approvals.two_can_publish_templates().await.unwrap());
    // **An account whose stored role is `admin` counts as an approver on MySQL and not on PostgreSQL** — the
    // Java query's behaviour, and this one's, because both compare `role` with `'ADMIN'` in SQL (Java's `in`, this
    // crate's `=` per role) and MySQL's default collation compares without case. `Role.of("admin")` is unreadable and authorizes nothing; the count is the
    // settings screen's "could four-eyes be honoured", so on MySQL such an account makes it answer yes for an
    // approver who cannot approve. Pinned per engine, as the Java side behaves, and recorded in the README.
    let only_lowercase = match database {
        Database::MySql(_) => format!("update t_user set is_active = {active} where binary role = 'admin'"),
        Database::PostgreSql(_) => format!("update t_user set is_active = {active} where role = 'admin'"),
    };
    execute(database, &[format!("update t_user set is_active = {inactive}"), only_lowercase]).await;
    let counted = approvals.any_active().await.unwrap();
    assert_eq!(counted, matches!(database, Database::MySql(_)), "a stored role `admin` counted as an approver");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_java_matrix_on_mysql() {
    the_matrix_on(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_java_matrix_on_postgresql() {
    the_matrix_on(Engine::PostgreSql).await;
}

//! `t_issue` and `t_issue_triage_event` as SeaORM entities — the declarations the repository's statements are built
//! from, held to the migrated schema by `parity::check_entities` on both engines (persistence/suite.rs).
//!
//! **Each `Model` mirrors the schema, not the module's rows**: a column the schema lets be null is an `Option` here
//! even where `IssueRow` has always read it as text (`identifier`, `source`, `severity`), so that the check can hold
//! the declaration to the schema; the repository converts.
//!
//! **The entities stay in this file.** Only the models, the columns and the active models leave it: `Entity` is not
//! exported, so `issue::Entity::find()` — a read of every target's rows with no visibility — does not compile in the
//! repository. A reader's query goes through [`visible_issues`]; the unrestricted reads (by id, by fingerprint,
//! the sweeps) go through [`issues`], named for what they are.

use sea_orm::{DeleteMany, EntityTrait, QueryTrait, Select, UpdateMany};
use vectispire_cp_db::orm::{TargetEntity, Visible};
use vectispire_cp_db::{Tx, Visibility};

mod issue {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_issue")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub repo_id: Option<i64>,
        pub container_id: Option<i64>,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub fingerprint: String,
        #[sea_orm(column_name = "type", column_type = "String(StringLen::N(50))")]
        pub type_: String,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub identifier: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub package_name: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub package_version: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub purl: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(500))")]
        pub file_path: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(3))")]
        pub owasp_category: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub source: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(200))")]
        pub tool: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(100))")]
        pub tool_name: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(100))")]
        pub tool_version: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(40))")]
        pub import_source: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub severity: Option<String>,
        pub epss_score: Option<f64>,
        pub is_kev: bool,
        pub cvss_score: Option<f64>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub cvss_vector: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub fix_state: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub fix_versions: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(500))")]
        pub link: Option<String>,
        #[sea_orm(column_type = "Text")]
        pub description: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub reachability: String,
        #[sea_orm(column_type = "Text")]
        pub reachable_symbols: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(20))")]
        pub state: String,
        pub first_seen_at: OffsetDateTime,
        pub last_seen_at: OffsetDateTime,
        pub resolved_at: Option<OffsetDateTime>,
        pub resolution_seconds: Option<i64>,
        pub sla_breach_signalled_at: Option<OffsetDateTime>,
        pub first_seen_scan_id: Option<i64>,
        pub last_seen_scan_id: Option<i64>,
        pub times_seen: i32,
        #[sea_orm(column_type = "String(StringLen::N(30))")]
        pub triage_status: String,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub triage_justification: Option<String>,
        #[sea_orm(column_type = "Text")]
        pub triage_comment: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub triaged_by: Option<String>,
        pub triaged_at: Option<OffsetDateTime>,
        pub triage_expires_at: Option<OffsetDateTime>,
        #[sea_orm(column_type = "String(StringLen::N(30))")]
        pub triage_requested_status: Option<String>,
        pub is_direct_dependency: Option<bool>,
        pub line: Option<i32>,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub ticket_ref: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(500))")]
        pub ticket_url: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub ticket_attached_by: Option<String>,
        pub revision: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod triage_event {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_issue_triage_event")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub issue_id: i64,
        #[sea_orm(column_type = "String(StringLen::N(30))")]
        pub from_status: String,
        #[sea_orm(column_type = "String(StringLen::N(30))")]
        pub to_status: String,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub justification: Option<String>,
        #[sea_orm(column_type = "custom(\"longtext\")")]
        pub comment: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub actor: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(20))")]
        pub origin: String,
        pub occurred_at: OffsetDateTime,
        pub expires_at: Option<OffsetDateTime>,
        #[sea_orm(column_type = "String(StringLen::N(30))")]
        pub requested_status: Option<String>,
        pub scan_id: Option<i64>,
        pub previous_resolved_at: Option<OffsetDateTime>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) use issue::{ActiveModel as IssueActive, Column as IssueColumn, Model as IssueModel};
pub(crate) use triage_event::{Column as TriageEventColumn, Entity as TriageEvents, Model as TriageEventModel};

impl TargetEntity for issue::Entity {
    type Table = vectispire_cp_db::query::Issues;
}

/// The issues a reader may see — the only way this crate selects them for a reader.
pub(crate) fn visible_issues(visibility: &Visibility) -> Visible<issue::Entity> {
    Visible::find(visibility)
}

/// Every issue, **whatever the reader may see**: for a lookup the service then holds to the reader's visibility
/// (`requireVisible`), and for the sweeps, which answer no reader.
pub(crate) fn issues() -> Select<issue::Entity> {
    issue::Entity::find()
}

/// Writes, which widen no reader's view, by name — so that the repository needs no name for the entity itself.
pub(crate) fn update_issues() -> UpdateMany<issue::Entity> {
    issue::Entity::update_many()
}

pub(crate) fn delete_issues() -> DeleteMany<issue::Entity> {
    issue::Entity::delete_many()
}

/// One issue inserted: its generated key.
pub(crate) async fn insert_issue(tx: &mut Tx, row: IssueActive) -> Result<i64, sqlx::Error> {
    vectispire_cp_db::orm::insert_returning_id::<issue::Entity>(tx, issue::Entity::insert(row).into_query()).await
}

/// The two tables, for `parity::check_entities` — run by this crate's suite on both engines; no start-up runs
/// `parity::check` for any module yet.
#[cfg(test)]
pub fn tables() -> Result<Vec<vectispire_cp_db::parity::EntityTable>, String> {
    Ok(vec![
        vectispire_cp_db::orm::entity_table::<issue::Entity>()?,
        vectispire_cp_db::orm::entity_table::<triage_event::Entity>()?,
    ])
}

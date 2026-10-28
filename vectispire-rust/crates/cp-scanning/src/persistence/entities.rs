//! `t_scan` and `t_finding` as SeaORM entities — the declarations `catalog_queries` builds its statements from, held
//! to the migrated schema by `parity::check_entities` on both engines (persistence/tests.rs).
//!
//! **Only the catalog's reads are built from them.** The scan lifecycle — the claim, the lease, the result — keeps its
//! compile-checked `query!` statements in `mysql.rs` and `postgres.rs`; both kinds run on the same [`Tx`].
//!
//! A scan's payload columns (`sbom`, `cves`, `summary`) are declared for the parity check and read by name only: a
//! catalog read selects the columns it answers with, never the row, so that listing a history does not carry every
//! SBOM of it.
//!
//! [`Tx`]: vectispire_cp_db::Tx

mod scan {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_scan")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub branch: String,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub sub_path: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub status: String,
        #[sea_orm(column_type = "custom(\"longtext\")")]
        pub sbom: Option<String>,
        #[sea_orm(column_type = "custom(\"longtext\")")]
        pub cves: Option<String>,
        #[sea_orm(column_type = "custom(\"longtext\")")]
        pub summary: Option<String>,
        pub duration_ms: Option<i64>,
        pub findings_count: i32,
        pub new_issues_count: i32,
        pub resolved_issues_count: i32,
        #[sea_orm(column_type = "Text")]
        pub error: Option<String>,
        pub created_at: OffsetDateTime,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub version: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub project_type: Option<String>,
        pub repo_id: Option<i64>,
        pub container_id: Option<i64>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub required_agent_label: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub claimed_by: Option<String>,
        pub claimed_at: Option<OffsetDateTime>,
        pub lease_expires_at: Option<OffsetDateTime>,
        pub attempts: i32,
        pub not_before: Option<OffsetDateTime>,
        #[sea_orm(column_type = "String(StringLen::N(512))")]
        pub detected_languages: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(512))")]
        pub sast_languages: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub examined_types: Option<String>,
        #[sea_orm(column_type = "custom(\"longtext\")")]
        pub plugin_steps: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod finding {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_finding")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub scan_id: i64,
        #[sea_orm(column_name = "type", column_type = "String(StringLen::N(50))")]
        pub type_: String,
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub severity: Option<String>,
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
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub source: String,
        pub epss_score: Option<f64>,
        pub is_kev: bool,
        pub created_at: OffsetDateTime,
        pub cvss_score: Option<f64>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub cvss_vector: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub fix_state: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub fix_versions: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(500))")]
        pub link: Option<String>,
        pub issue_id: Option<i64>,
        pub is_direct_dependency: Option<bool>,
        pub line: Option<i32>,
        #[sea_orm(column_type = "Text")]
        pub description: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub reachability: String,
        #[sea_orm(column_type = "Text")]
        pub reachable_symbols: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(3))")]
        pub owasp_category: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(200))")]
        pub tool: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(100))")]
        pub tool_name: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(100))")]
        pub tool_version: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) use finding::{Column as FindingColumn, Entity as Findings, Model as FindingModel};
pub(crate) use scan::{Column as ScanColumn, Entity as Scans};

/// The two tables, for `parity::check_entities` — run by this crate's suite on both engines.
#[cfg(test)]
pub fn tables() -> Result<Vec<vectispire_cp_db::parity::EntityTable>, String> {
    Ok(vec![
        vectispire_cp_db::orm::entity_table::<scan::Entity>()?,
        vectispire_cp_db::orm::entity_table::<finding::Entity>()?,
    ])
}

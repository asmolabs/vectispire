//! The five tables forges owns as SeaORM entities — `t_forge_connection` (V74), `t_forge_discovery` (V76, V80),
//! `t_forge_repository` (V76), `t_forge_import_link` (V78) and `t_forge_review_reading` (V81) — held to the migrated
//! schema by `parity::check_entities` (persistence/tests.rs).
//!
//! **None is a target's rows read for a reader**: the routes are administrators' and name no target, the import links
//! and the readings are read by repository id once a caller is past that gate. No `Visible` here.

pub(crate) mod connection {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_forge_connection")]
    pub struct Model {
        /// A UUID the module writes.
        #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(36))")]
        pub id: String,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub name: String,
        #[sea_orm(column_type = "String(StringLen::N(20))")]
        pub kind: String,
        #[sea_orm(column_type = "String(StringLen::N(40))")]
        pub edition: String,
        #[sea_orm(column_type = "String(StringLen::N(512))")]
        pub base_url: String,
        #[sea_orm(column_type = "String(StringLen::N(100))")]
        pub owner: Option<String>,
        pub internal_network: bool,
        #[sea_orm(column_type = "custom(\"longtext\")")]
        pub ca_pem: Option<String>,
        /// Sealed, never selected for a view.
        #[sea_orm(column_type = "String(StringLen::N(2048))")]
        pub token: String,
        #[sea_orm(column_type = "String(StringLen::N(40))")]
        pub credential_kind: String,
        #[sea_orm(column_type = "String(StringLen::N(1000))")]
        pub scopes: Option<String>,
        pub can_write: Option<bool>,
        pub token_expires_at: Option<OffsetDateTime>,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub forge_version: Option<String>,
        pub probed_at: OffsetDateTime,
        pub created_at: OffsetDateTime,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub created_by: String,
        pub updated_at: OffsetDateTime,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub updated_by: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod discovery {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_forge_discovery")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        #[sea_orm(column_type = "Char(Some(36))")]
        pub connection_id: String,
        #[sea_orm(column_type = "String(StringLen::N(20))")]
        pub state: String,
        #[sea_orm(column_type = "String(StringLen::N(40))")]
        pub reason: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(2000))")]
        pub detail: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(36))")]
        pub active_key: Option<String>,
        pub requested_at: OffsetDateTime,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub requested_by: String,
        #[sea_orm(column_type = "String(StringLen::N(100))")]
        pub claimed_by: Option<String>,
        pub lease_expires_at: Option<OffsetDateTime>,
        pub attempts: i32,
        pub started_at: Option<OffsetDateTime>,
        pub finished_at: Option<OffsetDateTime>,
        pub namespaces_seen: i32,
        pub repositories_seen: i32,
        pub repositories_skipped: i32,
        pub requests_made: i32,
        pub rate_limit_wait_seconds: i64,
        pub rate_limit_reset_at: Option<OffsetDateTime>,
        pub new_count: Option<i32>,
        pub changed_count: Option<i32>,
        pub gone_count: Option<i32>,
        #[sea_orm(column_type = "custom(\"longtext\")")]
        pub unreadable_namespaces: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod repository {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_forge_repository")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        #[sea_orm(column_type = "Char(Some(36))")]
        pub connection_id: String,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub forge_id: String,
        #[sea_orm(column_type = "String(StringLen::N(1000))")]
        pub full_path: String,
        #[sea_orm(column_type = "String(StringLen::N(1000))")]
        pub namespace_path: String,
        pub personal: bool,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub name: String,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub default_branch: Option<String>,
        pub archived: Option<bool>,
        pub fork: Option<bool>,
        #[sea_orm(column_type = "String(StringLen::N(20))")]
        pub visibility: Option<String>,
        pub last_activity_at: Option<OffsetDateTime>,
        #[sea_orm(column_type = "String(StringLen::N(100))")]
        pub language: Option<String>,
        pub size_bytes: Option<i64>,
        #[sea_orm(column_type = "String(StringLen::N(1024))")]
        pub http_url: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(1024))")]
        pub ssh_url: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(1024))")]
        pub web_url: Option<String>,
        pub first_seen_by: i64,
        pub first_seen_at: OffsetDateTime,
        pub last_seen_by: i64,
        pub last_seen_at: OffsetDateTime,
        pub changed_by: Option<i64>,
        #[sea_orm(column_type = "String(StringLen::N(1500))")]
        pub change_summary: Option<String>,
        pub gone_by: Option<i64>,
        pub gone_at: Option<OffsetDateTime>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod link {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_forge_import_link")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub repository_id: i64,
        #[sea_orm(column_type = "Char(Some(36))")]
        pub connection_id: String,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub forge_id: String,
        pub discovery_id: i64,
        pub imported_at: OffsetDateTime,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub imported_by: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) mod reading {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_forge_review_reading")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub repository_id: i64,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub wanted_branch: String,
        #[sea_orm(column_type = "String(StringLen::N(20))")]
        pub state: String,
        #[sea_orm(column_type = "Char(Some(36))")]
        pub connection_id: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub forge_id: Option<String>,
        pub window_days: i32,
        pub read_at: Option<OffsetDateTime>,
        #[sea_orm(column_type = "String(StringLen::N(1000))")]
        pub reason: Option<String>,
        #[sea_orm(column_type = "custom(\"longtext\")")]
        pub evidence: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub evidence_sha256: Option<String>,
        pub claimed_until: Option<OffsetDateTime>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// The five tables, for `parity::check_entities`.
#[cfg(test)]
pub fn tables() -> Result<Vec<vectispire_cp_db::parity::EntityTable>, String> {
    use vectispire_cp_db::orm::entity_table;
    Ok(vec![
        entity_table::<connection::Entity>()?,
        entity_table::<discovery::Entity>()?,
        entity_table::<repository::Entity>()?,
        entity_table::<link::Entity>()?,
        entity_table::<reading::Entity>()?,
    ])
}

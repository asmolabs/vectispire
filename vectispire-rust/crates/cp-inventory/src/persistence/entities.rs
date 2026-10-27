//! The inventory's six tables as SeaORM entities — the declarations the repository's statements are built from, held
//! to the migrated schema by `parity::check_entities` on both engines (persistence/tests.rs).
//!
//! None of them is read for a reader through a visibility: the inventory narrows what it read afterwards, by the rule
//! Java's services apply (a component naming a repository is the repository's), and no route reads these tables but
//! through those services. The flags are `bit(1)` on MySQL, `boolean` on PostgreSQL; both are a `Boolean` here.

/// What every entity here declares beside its model: no relation, the default behaviour.
macro_rules! no_relations {
    () => {
        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    };
}

pub mod component {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_component")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub scan_id: i64,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub name: String,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub version: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(500))")]
        pub purl: Option<String>,
        #[sea_orm(column_name = "type", column_type = "String(StringLen::N(50))")]
        pub type_: Option<String>,
        pub is_direct: Option<bool>,
        pub repo_id: Option<i64>,
        pub container_id: Option<i64>,
        pub scan_created_at: Option<OffsetDateTime>,
        #[sea_orm(column_type = "String(StringLen::N(10))")]
        pub origin: Option<String>,
        pub build_sbom_id: Option<i64>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub scanned_version: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(500))")]
        pub scanned_purl: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub declared_license: Option<String>,
    }

    no_relations!();
}

pub mod build_sbom {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_build_sbom")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub source_id: i64,
        #[sea_orm(column_type = "String(StringLen::N(40))")]
        pub source_slug: String,
        pub repo_id: i64,
        #[sea_orm(column_type = "String(StringLen::N(10))")]
        pub spec_version: String,
        #[sea_orm(column_type = "String(StringLen::N(200))")]
        pub tool: Option<String>,
        pub components_count: i32,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub commit_sha: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub branch_name: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub document_sha256: String,
        pub imported_at: OffsetDateTime,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub imported_by: String,
        #[sea_orm(column_type = "Char(Some(36))")]
        pub api_key_id: String,
    }

    no_relations!();
}

pub mod build_sbom_component {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_build_sbom_component")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub import_id: i64,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub name: String,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub version: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(500))")]
        pub purl: Option<String>,
        #[sea_orm(column_name = "type", column_type = "String(StringLen::N(50))")]
        pub type_: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub license: Option<String>,
    }

    no_relations!();
}

pub mod license_policy {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_license_policy")]
    pub struct Model {
        /// The singleton's `1`, written by the statement, not generated.
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: i64,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub disallowed_categories: String,
        #[sea_orm(column_type = "Text")]
        pub allowed_licenses: Option<String>,
        #[sea_orm(column_type = "Text")]
        pub disallowed_licenses: Option<String>,
        #[sea_orm(column_type = "custom(\"legacy_timestamp_zoned\")")]
        pub updated_at: OffsetDateTime,
    }

    no_relations!();
}

pub mod api_endpoint {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_api_endpoint")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub scan_id: i64,
        pub repository_id: Option<i64>,
        #[sea_orm(column_type = "String(StringLen::N(20))")]
        pub http_method: String,
        #[sea_orm(column_type = "String(StringLen::N(1000))")]
        pub path: String,
        pub auth_required: bool,
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub auth_type: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(20))")]
        pub visibility: String,
        #[sea_orm(column_type = "String(StringLen::N(1000))")]
        pub file_path: Option<String>,
        pub line_number: Option<i32>,
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub framework: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub operation_id: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(500))")]
        pub summary: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub tags: Option<String>,
        pub created_at: OffsetDateTime,
    }

    no_relations!();
}

pub mod api_contract {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_api_contract")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub repository_id: i64,
        pub scan_id: Option<i64>,
        #[sea_orm(column_type = "String(StringLen::N(1000))")]
        pub contract_path: String,
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub format: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub title: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub version: Option<String>,
        pub endpoints_count: i32,
        pub created_at: OffsetDateTime,
    }

    no_relations!();
}

/// The six tables, for `parity::check_entities` — run by this crate's suite on both engines.
#[cfg(test)]
pub fn tables() -> Result<Vec<vectispire_cp_db::parity::EntityTable>, String> {
    use vectispire_cp_db::orm::entity_table;
    Ok(vec![
        entity_table::<component::Entity>()?,
        entity_table::<build_sbom::Entity>()?,
        entity_table::<build_sbom_component::Entity>()?,
        entity_table::<license_policy::Entity>()?,
        entity_table::<api_endpoint::Entity>()?,
        entity_table::<api_contract::Entity>()?,
    ])
}

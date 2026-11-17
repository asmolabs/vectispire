//! The four tables compliance owns as SeaORM entities — `t_control_declaration` (V26, V92), `t_compliance_snapshot`
//! (V28), `t_ai_review_result` (V1, V31, V42, V62, V84) and `t_owasp_weekly_coverage` (V67) — held to the migrated
//! schema by `parity::check_entities` (persistence/tests.rs).
//!
//! **Three of them are no target's rows**, and are exported whole: a declaration is a statement about the management
//! system ("is A.8.28 applicable to us" has no target), a snapshot describes the whole estate as the deployment saw
//! it, which is what makes two months comparable, and a report's row is read by its repository after the route has
//! settled that the reader may see it. **The weekly record is a target's**: its entity stays in this file, and a
//! reader's sum goes through [`visible_weekly`], whose constructor takes the [`Visibility`].

use sea_orm::{EntityTrait, QueryTrait, Select};
use vectispire_cp_db::Visibility;
use vectispire_cp_db::orm::{TargetEntity, Visible};

mod declaration {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_control_declaration")]
    pub struct Model {
        /// A UUID the module writes, not a key the engine generates.
        #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(36))")]
        pub id: String,
        #[sea_orm(column_type = "String(StringLen::N(32))")]
        pub framework: String,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub control_id: String,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub applicability: String,
        #[sea_orm(column_type = "Text")]
        pub justification: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(32))")]
        pub implementation: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub evidence_source: String,
        #[sea_orm(column_type = "Text")]
        pub external_evidence: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub control_owner: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub decided_by: Option<String>,
        pub decided_at: OffsetDateTime,
        pub reviewed_at: Option<OffsetDateTime>,
        pub review_due_at: Option<OffsetDateTime>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod snapshot {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_compliance_snapshot")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(36))")]
        pub id: String,
        /// `yyyy-MM`, a `varchar(7)` and not a `char(7)`: PostgreSQL's `bpchar` failed Hibernate's validation (V28).
        #[sea_orm(column_type = "String(StringLen::N(7))")]
        pub period: String,
        #[sea_orm(column_type = "String(StringLen::N(32))")]
        pub framework: String,
        pub score: i32,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub status: String,
        pub targets: i32,
        pub observed_targets: i32,
        pub fresh_targets: i32,
        pub freshness_days: i32,
        pub eol_enabled: bool,
        pub code_analysis_reaches: bool,
        pub controls_total: i32,
        pub controls_declared: i32,
        pub soa_findings: i32,
        pub captured_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod review {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_ai_review_result")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub scan_id: i64,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub model: String,
        #[sea_orm(column_type = "Text")]
        pub prompt: String,
        #[sea_orm(column_type = "Text")]
        pub response: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(50))")]
        pub status: String,
        #[sea_orm(column_type = "String(StringLen::N(500))")]
        pub error: Option<String>,
        pub created_at: OffsetDateTime,
        #[sea_orm(column_type = "custom(\"longtext\")")]
        pub inputs: Option<String>,
        pub deadline_at: Option<OffsetDateTime>,
        pub repo_id: Option<i64>,
        #[sea_orm(column_type = "custom(\"longtext\")")]
        pub evidence_identifiers: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod weekly {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_owasp_weekly_coverage")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub week_start: OffsetDateTime,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub target_kind: String,
        pub target_id: i64,
        #[sea_orm(column_type = "String(StringLen::N(3))")]
        pub category: String,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub state: String,
        pub open_count: i64,
        pub settled_count: i64,
        pub captured_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) use declaration::{
    ActiveModel as DeclarationActive, Column as DeclarationColumn, Entity as Declarations, Model as DeclarationModel,
};
pub(crate) use review::{ActiveModel as ReviewActive, Column as ReviewColumn, Entity as Reviews, Model as ReviewModel};
pub(crate) use snapshot::{
    ActiveModel as SnapshotActive, Column as SnapshotColumn, Entity as Snapshots, Model as SnapshotModel,
};
pub(crate) use weekly::{ActiveModel as WeeklyActive, Column as WeeklyColumn};

impl TargetEntity for weekly::Entity {
    type Table = vectispire_cp_db::query::OwaspWeeklyCoverage;
}

/// The weekly rows a reader may see — the only way this crate selects them for a reader.
pub(crate) fn visible_weekly(visibility: &Visibility) -> Visible<weekly::Entity> {
    Visible::find(visibility)
}

/// Every weekly row, **whatever the reader may see**: the capture's gate and its rewrite, the purges, the orphan sweep
/// — the record of the whole estate, as the compliance history is.
pub(crate) fn weekly() -> Select<weekly::Entity> {
    weekly::Entity::find()
}

pub(crate) fn delete_weekly() -> sea_orm::DeleteMany<weekly::Entity> {
    weekly::Entity::delete_many()
}

pub(crate) fn insert_weekly(rows: Vec<WeeklyActive>) -> sea_orm::sea_query::InsertStatement {
    weekly::Entity::insert_many(rows).into_query()
}

/// The four tables, for `parity::check_entities`.
#[cfg(test)]
pub fn tables() -> Result<Vec<vectispire_cp_db::parity::EntityTable>, String> {
    Ok(vec![
        vectispire_cp_db::orm::entity_table::<declaration::Entity>()?,
        vectispire_cp_db::orm::entity_table::<snapshot::Entity>()?,
        vectispire_cp_db::orm::entity_table::<review::Entity>()?,
        vectispire_cp_db::orm::entity_table::<weekly::Entity>()?,
    ])
}

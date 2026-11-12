//! `t_gate_policy` and `t_gate_verdict` as SeaORM entities — the declarations the repositories' statements are
//! built from, held to the migrated schema by `parity::check_entities` on both engines (persistence/tests.rs).
//!
//! **The entities stay in this file**, as in the issues module: `Entity` is not exported, so a read of every
//! target's verdicts with no visibility — `verdict::Entity::find()` — does not compile in the repository. A
//! reader's page goes through [`visible_verdicts`]; the reads that answer no reader (a target's own verdict, the
//! newest for the indicator, the purge) go through [`verdicts`], named for what they are.
//!
//! On MySQL four of the policy's flags are `bit(1)` (V1) and the three added since are `tinyint(1)`; both are a
//! `Boolean` here, and the parity check accepts either spelling.

use sea_orm::{DeleteMany, EntityTrait, QueryTrait, Select};
use vectispire_cp_db::Visibility;
use vectispire_cp_db::orm::{TargetEntity, Visible};

mod policy {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_gate_policy")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        #[sea_orm(column_type = "String(StringLen::N(20))")]
        pub target_kind: String,
        pub target_id: i64,
        pub version: i32,
        pub is_active: Option<bool>,
        #[sea_orm(column_type = "String(StringLen::N(20))")]
        pub fail_on_severity: Option<String>,
        pub fail_on_kev: bool,
        pub fixable_only: bool,
        pub include_triaged: bool,
        pub include_ai_review: bool,
        pub fail_on_uncovered_languages: bool,
        pub include_plugins: bool,
        #[sea_orm(column_type = "Text")]
        pub note: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub created_by: Option<String>,
        pub created_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod verdict {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_gate_verdict")]
    pub struct Model {
        /// A UUID the gate writes, not a key the engine generates.
        #[sea_orm(primary_key, auto_increment = false, column_type = "Char(Some(36))")]
        pub id: String,
        pub repo_id: Option<i64>,
        pub container_id: Option<i64>,
        pub passed: bool,
        pub evaluated: i32,
        pub violations: i32,
        pub critical_count: i64,
        pub high_count: i64,
        pub medium_count: i64,
        pub low_count: i64,
        #[sea_orm(column_type = "String(StringLen::N(20))")]
        pub fail_on_severity: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(32))")]
        pub policy_source: String,
        pub policy_version: Option<i64>,
        pub relaxations_ignored: bool,
        pub decided_at: OffsetDateTime,
        #[sea_orm(column_type = "String(StringLen::N(255))")]
        pub decided_by: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub ip_address: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

// Policies are no target's rows — the gate's configuration, read whole — so their entity is exported as it is.
pub(crate) use policy::{
    ActiveModel as PolicyActive, Column as PolicyColumn, Entity as Policies, Model as PolicyModel,
};
pub(crate) use verdict::{ActiveModel as VerdictActive, Column as VerdictColumn, Model as VerdictModel};

impl TargetEntity for verdict::Entity {
    type Table = vectispire_cp_db::query::GateVerdicts;
}

/// The verdicts a reader may see — the only way this crate selects them for a reader.
pub(crate) fn visible_verdicts(visibility: &Visibility) -> Visible<verdict::Entity> {
    Visible::find(visibility)
}

/// Every verdict, **whatever the reader may see**: a target's own verdict (the caller has settled the target), the
/// newest for the indicator, the register of a reader who sees everything.
pub(crate) fn verdicts() -> Select<verdict::Entity> {
    verdict::Entity::find()
}

pub(crate) fn delete_verdicts() -> DeleteMany<verdict::Entity> {
    verdict::Entity::delete_many()
}

pub(crate) fn insert_verdict(row: VerdictActive) -> sea_orm::sea_query::InsertStatement {
    verdict::Entity::insert(row).into_query()
}

/// The two tables, for `parity::check_entities` — run by this crate's suite on both engines.
#[cfg(test)]
pub fn tables() -> Result<Vec<vectispire_cp_db::parity::EntityTable>, String> {
    Ok(vec![
        vectispire_cp_db::orm::entity_table::<policy::Entity>()?,
        vectispire_cp_db::orm::entity_table::<verdict::Entity>()?,
    ])
}

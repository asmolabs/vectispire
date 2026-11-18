//! The three tables threat intelligence owns as SeaORM entities — `t_threat_intel_feed` (V12, V43, V45),
//! `t_threat_intel_sync` (V12, V43, V45, V47) and `t_epss_score` (V45) — held to the migrated schema by
//! `parity::check_entities` (persistence/tests.rs).
//!
//! **None of them is a target's.** The catalogue and the scores are the world's, read by every reader alike, and the
//! sync row is the deployment's: nothing here takes a [`vectispire_cp_db::Visibility`]. What a reader may see is
//! decided on the issues the figures are put beside, by the module that owns them.

mod feed {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_threat_intel_feed")]
    pub struct Model {
        /// The CVE as the catalogue spells it, upper-case: assigned, not generated.
        #[sea_orm(primary_key, auto_increment = false, column_type = "String(StringLen::N(64))")]
        pub cve_id: String,
        pub is_kev: bool,
        /// V12's columns: MySQL's `timestamp`, to the second; `timestamp with time zone` on PostgreSQL.
        #[sea_orm(column_type = "custom(\"legacy_timestamp_zoned\")")]
        pub date_added: Option<OffsetDateTime>,
        #[sea_orm(column_type = "custom(\"legacy_timestamp_zoned\")")]
        pub updated_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod sync {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_threat_intel_sync")]
    pub struct Model {
        /// Always [`super::super::SINGLETON_ID`].
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: i64,
        /// V12's column, to the second on MySQL; every instant V43 and later added is `datetime(6)`.
        #[sea_orm(column_type = "custom(\"legacy_timestamp_zoned\")")]
        pub last_synced_at: Option<OffsetDateTime>,
        pub cve_count: i64,
        pub kev_count: i64,
        #[sea_orm(column_type = "String(StringLen::N(32))")]
        pub status: String,
        #[sea_orm(column_type = "String(StringLen::N(32))")]
        pub kev_catalog_version: Option<String>,
        pub kev_released_at: Option<OffsetDateTime>,
        pub last_attempt_at: Option<OffsetDateTime>,
        #[sea_orm(column_type = "String(StringLen::N(500))")]
        pub last_error: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(32))")]
        pub epss_status: String,
        pub epss_synced_at: Option<OffsetDateTime>,
        #[sea_orm(column_type = "String(StringLen::N(32))")]
        pub epss_model_version: Option<String>,
        pub epss_score_date: Option<OffsetDateTime>,
        pub epss_count: i64,
        pub epss_generation: Option<i64>,
        pub epss_previous_generation: Option<i64>,
        pub epss_attempt_at: Option<OffsetDateTime>,
        pub epss_lease_until: Option<OffsetDateTime>,
        pub epss_claim: Option<i64>,
        #[sea_orm(column_type = "String(StringLen::N(500))")]
        pub epss_error: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod score {
    use sea_orm::entity::prelude::*;

    /// No `Eq`: two of the columns are doubles.
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "t_epss_score")]
    pub struct Model {
        /// Leads the key: every read and every delete names one.
        #[sea_orm(primary_key, auto_increment = false)]
        pub generation: i64,
        #[sea_orm(primary_key, auto_increment = false, column_type = "String(StringLen::N(32))")]
        pub cve_id: String,
        pub score: f64,
        pub percentile: f64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub(crate) use feed::{ActiveModel as FeedActive, Column as FeedColumn, Entity as Feeds, Model as FeedModel};
pub(crate) use score::{ActiveModel as ScoreActive, Column as ScoreColumn, Entity as Scores, Model as ScoreModel};
pub(crate) use sync::{ActiveModel as SyncActive, Column as SyncColumn, Entity as Syncs, Model as SyncModel};

/// The three tables, for `parity::check_entities`.
#[cfg(test)]
pub fn tables() -> Result<Vec<vectispire_cp_db::parity::EntityTable>, String> {
    Ok(vec![
        vectispire_cp_db::orm::entity_table::<feed::Entity>()?,
        vectispire_cp_db::orm::entity_table::<sync::Entity>()?,
        vectispire_cp_db::orm::entity_table::<score::Entity>()?,
    ])
}

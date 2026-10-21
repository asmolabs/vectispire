//! The ingestor the binary composes, held to Java's: `ScanIngestor` with `LicenseService`, `EnrichmentService` and
//! `EndOfLifeService`, all three unconditional beans.
//!
//! The binary composed none of the three, and nothing failed: the reference set states its sources case by case, so
//! only the composition can show that a source is missing. A stand-in is allowed, named here with the task that ends
//! it; when Phase 4 task 4.4 ports `threatintel`, this list shrinks in the same commit.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_scanning::ingestion::{NoBacklog, NoInventory};

fn unreachable_db() -> vectispire_cp_db::Db {
    let settings = DbSettings {
        url: DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: PoolSettings::default(),
        ca_pem: None,
    };
    vectispire_cp_db::Db::connect_lazy(&settings).unwrap()
}

#[tokio::test]
async fn the_ingestor_has_every_source_java_composes() {
    let ingestor = vectispire_cp_app::ingestion::ingestor(
        Arc::new(NoBacklog),
        Arc::new(NoInventory),
        vectispire_cp_settings::Settings::new(unreachable_db()),
        Arc::new(vectispire_cp_targets::SystemClock),
    );

    assert!(ingestor.licenses.is_some(), "Java's LicenseService is scanning's own, never a stand-in");
    assert!(ingestor.enricher.is_some(), "an absent enricher is a stand-in nobody named");
    assert!(ingestor.end_of_life.is_some(), "an absent end-of-life source is a stand-in nobody named");
    assert_eq!(
        ingestor.stand_ins(),
        vec![
            "enrichment: threatintel's EnrichmentService, Phase 4 task 4.4",
            "end of life: threatintel's EndOfLifeService, Phase 4 task 4.4",
        ],
    );
}

//! The jobs the binary runs once it has started, held to Java's `ApplicationReadyEvent` listeners of the modules
//! ported so far: the targets' orphan sweep and the agents' withheld-claim repair.
//!
//! The repair was ported, tested on both engines, and run by nothing — only the composition can show that. A module
//! ported later adds its listener here and to `ready_jobs` in the same commit.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};

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
async fn the_ready_jobs_are_java_s_listeners() {
    use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
    use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};

    let db = unreachable_db();
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    let targets = Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit: audit.clone(),
        scans: vectispire_cp_scanning::target_scans(db.clone(), Arc::new(vectispire_cp_targets::SystemClock)),
        backlog: Arc::new(vectispire_cp_targets::IssuesStandIn),
        purge: vectispire_cp_targets::PurgeRegistry::stand_ins(),
        encryption: Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap()),
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        clock: Arc::new(vectispire_cp_targets::SystemClock),
        visibility: None,
    }));
    let catalog = vectispire_cp_scanning::ScanCatalog::new(db.clone(), Arc::new(vectispire_cp_targets::SystemClock));
    let repair = Arc::new(vectispire_cp_agents::WithheldClaimRepair::new(
        db.clone(),
        catalog,
        targets.clone(),
        Arc::new(vectispire_cp_audit::AuditLogQuery::new(
            (*audit).clone(),
            Arc::new(vectispire_cp_audit::SystemClock),
            Vec::new(),
        )),
        audit,
        Arc::new(vectispire_cp_maintenance::OneShotJobs::new(db, Arc::new(vectispire_cp_maintenance::SystemClock))),
    ));

    let names: Vec<&str> = vectispire_cp_app::startup::ready_jobs(targets, repair).iter().map(|job| job.name).collect();
    assert_eq!(names, vec!["targets: the orphan sweep", "agents: withheld-claim-repair"]);
}

//! The notification centre's two routes against the contract they must not change (`openapi.json`): documented under
//! the same method and path, with Java's operation ids and markers, out of `cp-contract`'s `not-yet-ported/` — then
//! the router probed, so a route declared and not registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_module, check_published, probe,
};
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{RecordingAudit, StaticCredentials};
use vectispire_cp_http::routes::{NoVisibility, Routes};
use vectispire_cp_notifications::{NotificationTestService, NotificationsConfig};
use vectispire_cp_outbound::{OutboundPost, OutboundUrlGuard, PinnedHttpSender};

const DECLARED: &[(&str, &str, &str)] = &[
    ("GET", "/api/v1/notifications/channels", "getChannels"),
    ("POST", "/api/v1/notifications/test/{channelType}", "testChannel"),
];

fn config() -> NotificationsConfig {
    let db = vectispire_cp_db::Db::connect_lazy(&DbSettings {
        url: DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: PoolSettings::default(),
        ca_pem: None,
    })
    .unwrap();
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    NotificationsConfig {
        settings: vectispire_cp_settings::Settings::new(db.clone()),
        integrations: vectispire_cp_settings::Integrations::new(
            db.clone(),
            Vec::new(),
            Arc::new(time::OffsetDateTime::now_utc),
        ),
        db,
        encryption: Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap()),
        post: OutboundPost::new(
            OutboundUrlGuard::new(Vec::new()),
            PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        ),
        public_url: None,
        mail: None,
        mail_from: "vectispire@localhost".into(),
        clock: Arc::new(vectispire_cp_audit::SystemClock),
    }
}

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let config = config();
    let channels = vectispire_cp_notifications::channels(&config);
    let entries = vectispire_cp_notifications::routes(Arc::new(NotificationTestService::new(config, channels.all())));
    // `NotificationCenterController`'s markers: any account on the class, security lead on the test — it posts to
    // somebody else's channel. Any marker passes the registry's rules, so the one each route carries is held here.
    let markers: Vec<(String, String, Access)> = entries
        .iter()
        .map(|entry| (entry.decl().method.clone(), entry.decl().path.clone(), entry.decl().access))
        .collect();
    assert_eq!(
        markers,
        vec![
            ("GET".to_owned(), DECLARED[0].1.to_owned(), Access::Account),
            ("POST".to_owned(), DECLARED[1].1.to_owned(), Access::SecurityLead),
        ]
    );

    let declared: Vec<RouteDecl> = DECLARED.iter().map(|(method, path, id)| RouteDecl::new(method, path, id)).collect();
    let document = Document::embedded();
    let ours: BTreeSet<(String, String)> =
        declared.iter().map(|route| (route.method.clone(), route.path.clone())).collect();
    let not_ours = Allowlist::all_but(&document, &ours);
    assert_none(&check_module(&document, &declared, &Allowlist::committed()));
    assert_none(&check_published(&document, &Published::embedded(), Some(&declared)));

    let mut routes = Routes::new(NoVisibility);
    for entry in entries {
        routes = routes.route(entry);
    }
    let chain = Arc::new(Chain::new(
        ChainConfig::default(),
        Arc::new(StaticCredentials::default()),
        Arc::new(RecordingAudit::default()),
    ));
    let router = routes.build(&chain, None).unwrap();
    assert_none(&probe(&router, &document, &not_ours).await);
}

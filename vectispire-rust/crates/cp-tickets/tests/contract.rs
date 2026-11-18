//! The tickets' three routes against the contract they must not change (`openapi.json`): documented under the same
//! method and path, with Java's operation ids and markers, out of `cp-contract`'s `not-yet-ported/` — then the router
//! probed, so a route declared and not registered is caught too.

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
use vectispire_cp_http::routes::{NoVisibility, Routes, Visibility};
use vectispire_cp_outbound::{OutboundPost, OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_tickets::{Tickets, TicketsConfig};

const DECLARED: &[(&str, &str, &str)] = &[
    ("GET", "/api/v1/issues/{issueId}/tickets", "list_12"),
    ("POST", "/api/v1/issues/{issueId}/tickets", "create_5"),
    ("POST", "/api/v1/tickets/webhook/{provider}", "handleWebhook"),
];

fn tickets() -> Tickets {
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
    Tickets::new(TicketsConfig {
        settings: vectispire_cp_settings::Settings::new(db.clone()),
        integrations: vectispire_cp_settings::Integrations::new(
            db.clone(),
            Vec::new(),
            Arc::new(time::OffsetDateTime::now_utc),
        ),
        audit: Arc::new(vectispire_cp_audit::AuditLog::new(
            db.clone(),
            Arc::new(vectispire_cp_audit::NoMirror),
            Arc::new(vectispire_cp_audit::SystemClock),
            Vec::new(),
        )),
        db,
        encryption: Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap()),
        post: OutboundPost::new(
            OutboundUrlGuard::new(Vec::new()),
            PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        ),
        alerts: Arc::new(vectispire_cp_outbox::NotTold),
        clock: Arc::new(vectispire_cp_audit::SystemClock),
    })
}

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let entries = tickets().routes();
    // `TicketingController`'s markers — any account on the class, a writing account on the attach, both naming the
    // issue's target — and the webhook's `@OpenToAnonymous`: the tracker holds no session.
    let markers: Vec<(String, String, Access, Visibility)> = entries
        .iter()
        .map(|entry| {
            let decl = entry.decl();
            (decl.method.clone(), decl.path.clone(), decl.access, decl.visibility)
        })
        .collect();
    assert_eq!(
        markers,
        vec![
            ("GET".to_owned(), DECLARED[0].1.to_owned(), Access::Account, Visibility::Scoped),
            ("POST".to_owned(), DECLARED[1].1.to_owned(), Access::WriteAccount, Visibility::Scoped),
            ("POST".to_owned(), DECLARED[2].1.to_owned(), Access::Anonymous, Visibility::NamesNoTarget),
        ]
    );

    // The window read on the list, and the three ways a tracker proves itself on the webhook.
    let declared: Vec<RouteDecl> = vec![
        RouteDecl::new("GET", DECLARED[0].1, DECLARED[0].2).query("limit", false).query("offset", false),
        RouteDecl::new("POST", DECLARED[1].1, DECLARED[1].2),
        RouteDecl::new("POST", DECLARED[2].1, DECLARED[2].2)
            .header("x-gitlab-token", false)
            .header("x-hub-signature-256", false)
            .header("x-vectispire-token", false),
    ];
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

//! The advisor on a real server, with a fake Ollama on the loopback — Java's `AiAdvisorRoutesTest` and
//! `AiProviderSwitchRoutesTest`: the product's own advice when the review is off, the issue's figures before the
//! feeds', a hidden issue answered as an absent one and a CVE carried only where the caller cannot see answered as one
//! carried nowhere; with the review on, the model's answer, its fallback when it does not answer JSON, and — the
//! provider switched off — 409, with neither provider asked.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::float_cmp)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::routing::{get, post};
use vectispire_cp_ai::advisor::AdvisorError;
use vectispire_cp_ai::review::ReviewError;
use vectispire_cp_ai::{AiParts, Services};
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine, Mode, ScanTarget, Visibility};
use vectispire_cp_outbound::post::OutboundPost;
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_settings::{Integrations, Setting, Settings};
use vectispire_domain::integrations::Integration;
use vectispire_domain::secret::Secret;

/// The fake Ollama: what it was asked, and the chat answer it gives.
#[derive(Default)]
struct Fake {
    asked: Mutex<Vec<String>>,
    answer: Mutex<String>,
}

async fn fake_ollama(fake: Arc<Fake>) -> String {
    let (chat, tags) = (fake.clone(), fake);
    let app = Router::new()
        .route(
            "/api/chat",
            post(move |body: String| {
                let fake = chat.clone();
                async move {
                    fake.asked.lock().unwrap().push(format!("chat {body}"));
                    fake.answer.lock().unwrap().clone()
                }
            }),
        )
        .route(
            "/api/tags",
            get(move || {
                let fake = tags.clone();
                async move {
                    fake.asked.lock().unwrap().push("tags".to_owned());
                    r#"{"models":[{"name":"gemma4:12b-it-qat"},{"name":""},{"name":"llama3"}]}"#
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}/")
}

async fn set(db: &Db, setting: Setting, value: &str) {
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    Settings::new(db.clone()).set(&mut tx, setting, value).await.unwrap();
    tx.commit().await.unwrap();
}

fn only(repository: i64) -> Visibility {
    Visibility::Only(BTreeSet::from([ScanTarget::Repository(repository)]))
}

#[test]
fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = TestDatabase::start(Engine::MySql).await;
        let db = server.connect().await;
        server.sql_as_admin("insert into t_repository (id, url, branch, name) values (101, 'https://forge.example/a.git', 'main', 'a'), (102, 'https://forge.example/b.git', 'main', 'b')");
        server.sql_as_admin(
            "insert into t_issue (id, repo_id, fingerprint, type, state, identifier, severity, epss_score, is_kev, \
             package_name, package_version, purl, fix_versions, first_seen_at, last_seen_at, times_seen, \
             triage_status, reachability, revision) values \
             (1, 101, 'fp-1', 'vulnerability', 'open', 'CVE-2021-44228', 'CRITICAL', null, false, 'log4j-core', \
              '2.14.1', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', '2.17.1', '2026-01-01 00:00:00', \
              '2026-01-01 00:00:00', 1, 'untriaged', 'unknown', 0), \
             (2, 102, 'fp-2', 'vulnerability', 'open', 'CVE-2026-0009', 'HIGH', 0.42, true, 'openssl', '3.0.1', \
              null, null, '2026-01-01 00:00:00', '2026-01-01 00:00:00', 1, 'untriaged', 'unknown', 0)",
        );
        // The feeds: Log4Shell listed and scored.
        server.sql_as_admin("insert into t_threat_intel_feed (cve_id, is_kev, date_added, updated_at) values ('CVE-2021-44228', true, '2021-12-10 00:00:00', '2026-01-01 00:00:00')");
        server.sql_as_admin("insert into t_epss_score (generation, cve_id, score, percentile) values (5, 'CVE-2021-44228', 0.975, 0.9998)");
        server.sql_as_admin("update t_threat_intel_sync set epss_generation = 5, epss_count = 1, last_synced_at = '2026-01-01 00:00:00' where id = 1");

        let door = VaultDoor {
            sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
            guard: OutboundUrlGuard::new(Vec::new()),
        };
        let encryption = Arc::new(
            Encryption::new(
                &EncryptionConfig {
                    key: Some(Secret::new("dGhyb3dhd2F5LXRhcmdldHMta2V5LTMyLWJ5dGVzISE=")),
                    ..EncryptionConfig::default()
                },
                door,
            )
            .unwrap(),
        );
        let integrations =
            Arc::new(Integrations::new(db.clone(), Vec::new(), Arc::new(time::OffsetDateTime::now_utc)));
        let services = Services::new(AiParts {
            settings: Settings::new(db.clone()),
            integrations: integrations.clone(),
            post: OutboundPost::new(OutboundUrlGuard::new(Vec::new()), PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn)),
            encryption,
            issues: Arc::new(vectispire_cp_issues::IssueCatalog::new(db.clone())),
            feeds: vectispire_cp_threatintel::feeds::ThreatIntel::new(db.clone(), Arc::new(vectispire_cp_targets::SystemClock)),
        });

        the_products_own_advice(&services).await;
        let fake = Arc::new(Fake::default());
        set(&db, Setting::AiReviewOllamaUrl, &fake_ollama(fake.clone()).await).await;
        set(&db, Setting::AiReviewEnabled, "true").await;
        the_models_advice(&services, &fake).await;
        a_switched_off_provider_is_refused_not_replaced(&services, &fake, &integrations, &db).await;
    });
}

async fn the_products_own_advice(services: &Services) {
    let advisor = &services.advisor;
    // The issue's own figures are none, so the feeds answer: listed, 97.5 %.
    let advice = advisor.explain_issue(1, None, &Visibility::Everything).await.unwrap();
    let deterministic = advice.deterministic.as_ref().expect("written by the product");
    assert_eq!(
        (deterministic.kev, deterministic.exploit_probability),
        (vectispire_cp_threatintel::status::KevListing::Listed, Some(0.975))
    );
    assert_eq!(advice.vex_suggestion.status, "affected", "carried by an issue, and listed");
    assert_eq!(
        advice.remediation.cli_command,
        "mvn versions:use-dep-version -Dincludes=org.apache.logging.log4j:log4j-core -DdepVersion=2.17.1 -DforceVersion=true"
    );
    // The issue's own flag and score win: listed, 42 %.
    let own = advisor.explain_issue(2, Some("fr"), &Visibility::Everything).await.unwrap();
    assert_eq!(
        own.exploit_mechanics,
        "Listed in the CISA KEV catalogue: exploitation in the wild has been reported. EPSS probability: 42%."
    );

    // Hidden and absent alike.
    let hidden = advisor.explain_issue(2, None, &only(101)).await.unwrap_err();
    let absent = advisor.explain_issue(999, None, &only(101)).await.unwrap_err();
    assert!(
        matches!((&hidden, &absent), (AdvisorError::NotFound(a), AdvisorError::NotFound(b)) if a == b && a == "Issue not found.")
    );
    assert!(
        matches!(advisor.explain_issue(1, Some("de"), &Visibility::Everything).await, Err(AdvisorError::InvalidInput(m)) if m == "language must be one of en, fr.")
    );

    // A CVE carried only where the caller cannot see is answered as one carried nowhere.
    let elsewhere = advisor.explain_cve("CVE-2026-0009", None, &only(101)).await.unwrap();
    let nowhere = advisor.explain_cve("CVE-2026-0010", None, &only(101)).await.unwrap();
    assert_eq!(elsewhere.summary_explanation, "Vulnerability CVE-2026-0009: the affected component is unknown.");
    assert_eq!(nowhere.deterministic, elsewhere.deterministic, "same shape, nothing of the hidden issue");
    assert_eq!(elsewhere.deterministic.as_ref().unwrap().package_name, None);
    // Visible, it is the issue's advice — whatever the case the caller spelled it in.
    let visible = advisor.explain_cve("cve-2021-44228", None, &only(101)).await.unwrap();
    assert_eq!(visible.title, "Analysis and remediation for CVE-2021-44228 in log4j-core");
    // The feeds alone: listed, yet never `affected`.
    let alone = advisor.explain_cve("CVE-2021-44228", None, &only(102)).await.unwrap();
    assert_eq!(alone.vex_suggestion.status, "under_investigation");

    let reviews = &services.reviews;
    assert!(!reviews.is_enabled().await.unwrap());
    assert_eq!(reviews.selected_model().await.unwrap(), "gemma4:12b-it-qat");
}

async fn the_models_advice(services: &Services, fake: &Fake) {
    *fake.answer.lock().unwrap() = r#"{"message":{"role":"assistant","content":"```json\n{\"summary\":\"S\",\"mechanics\":\"M\",\"exposure\":\"E\",\"cli_command\":\"C\",\"vex_status\":\"affected\",\"vex_statement\":\"V\"}\n```"}}"#.to_owned();
    let advice = services.advisor.explain_issue(1, Some("fr"), &Visibility::Everything).await.unwrap();
    assert_eq!(advice.title, "Model analysis for CVE-2021-44228 (log4j-core)");
    assert_eq!((advice.summary_explanation.as_str(), advice.remediation.cli_command.as_str()), ("S", "C"));
    assert_eq!(advice.remediation.fix_action, "Upgrade to 2.17.1.", "the default when the model says nothing");
    assert_eq!(
        (advice.vex_suggestion.status.as_str(), advice.vex_suggestion.impact_statement.as_str()),
        ("affected", "V")
    );
    assert!(advice.deterministic.is_none(), "a model wrote it");
    let asked = fake.asked.lock().unwrap().drain(..).collect::<Vec<_>>();
    assert_eq!(asked.len(), 1);
    assert!(asked[0].contains("Explain this vulnerability in French"), "{}", asked[0]);
    assert!(asked[0].contains("KEV: listed in the CISA KEV catalogue, EPSS: 0.975"), "{}", asked[0]);
    assert!(asked[0].contains(r#""stream":false"#), "{}", asked[0]);

    // An answer that is not the JSON asked for: the product's own advice, not an error.
    *fake.answer.lock().unwrap() = r#"{"message":{"content":"I cannot help with that."}}"#.to_owned();
    let fallback = services.advisor.explain_issue(1, None, &Visibility::Everything).await.unwrap();
    assert!(fallback.deterministic.is_some());

    assert_eq!(
        services.reviews.available_models().await.unwrap(),
        ["gemma4:12b-it-qat", "llama3"],
        "the provider's own list"
    );
    assert!(services.reviews.provider_enabled().await.unwrap());
    fake.asked.lock().unwrap().clear();
}

async fn a_switched_off_provider_is_refused_not_replaced(
    services: &Services,
    fake: &Fake,
    integrations: &Integrations,
    db: &Db,
) {
    let ollama = Integration::by_key("ai.ollama").unwrap();
    integrations.switch_to(ollama, false, "admin").await.unwrap();
    let refused = services.advisor.explain_issue(1, None, &Visibility::Everything).await.unwrap_err();
    assert!(matches!(refused, AdvisorError::Review(ReviewError::Disabled(integration)) if integration == ollama));
    assert!(!services.reviews.provider_enabled().await.unwrap());
    assert_eq!(
        services.reviews.available_models().await.unwrap(),
        ["gemma4:12b-it-qat", "gemma4:e4b-it-qat"],
        "suggestions, nobody asked"
    );
    // The review off, the provider is not asked either: the product's advice.
    set(db, Setting::AiReviewEnabled, "false").await;
    assert!(services.advisor.explain_issue(1, None, &Visibility::Everything).await.unwrap().deterministic.is_some());
    assert!(fake.asked.lock().unwrap().is_empty(), "neither provider asked");
}

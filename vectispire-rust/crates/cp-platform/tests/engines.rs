//! The settings screen's rules on real servers, both engines: what each reader sees of the catalog, what a save
//! writes and audits, and every refusal — in `SettingsAdministrationService`'s words, with nothing written.
//!
//! The modules a save consults that are not ported yet are stand-ins whose answers each test sets.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::future::BoxFuture;
use support::Migrated;
use time::OffsetDateTime;
use vectispire_cp_audit::{
    AuditLog, Clock, Listener, ListenerError, NoMirror, Record, RequestActor, Signal, StoredEntry,
};
use vectispire_cp_db::{Db, Engine, Tx};
use vectispire_cp_platform::{
    AdministrationError, AiAfter, AiDestination, Applied, Approvers, Caller, CollaboratorError,
    SECURITY_SETTING_CHANGED, SettingsAdministration, Tracker,
};
use vectispire_cp_settings::{Setting, Settings};

const AT: i64 = 1_792_224_000; // 2026-10-17T08:00:00Z

#[derive(Debug)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(AT).unwrap()
    }
}

/// `access`' answers, set per test.
struct People {
    approver: AtomicBool,
    publishers: AtomicBool,
    signers: AtomicBool,
}

impl Approvers for People {
    fn any_active(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>> {
        Box::pin(async move { Ok(self.approver.load(Ordering::SeqCst)) })
    }
    fn two_can_publish_templates(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>> {
        Box::pin(async move { Ok(self.publishers.load(Ordering::SeqCst)) })
    }
    fn two_can_sign_off_checklists(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>> {
        Box::pin(async move { Ok(self.signers.load(Ordering::SeqCst)) })
    }
}

/// `tickets`: refuses any PEM that says so.
struct Pins;

impl Tracker for Pins {
    fn refuse_ca(&self, pem: &str) -> Option<String> {
        pem.contains("NOT A CA").then(|| "Tracker CA (PEM) — not a CA certificate.".to_owned())
    }
}

/// `ai`: refuses a public destination unless acknowledged, and records what it was asked.
#[derive(Default)]
struct Model {
    asked: Mutex<Vec<String>>,
    acknowledged: Mutex<Vec<String>>,
}

impl AiDestination for Model {
    fn refuse_destination<'a>(
        &'a self,
        after: AiAfter<'a>,
    ) -> BoxFuture<'a, Result<Option<String>, CollaboratorError>> {
        Box::pin(async move {
            self.asked.lock().unwrap().push(format!(
                "{} {:?} {:?} {}",
                after.provider, after.openai_url, after.ollama_url, after.allow_remote
            ));
            let public = after.provider == "openai" && !after.openai_url.is_some_and(|url| url.contains("internal"));
            Ok((public && !after.allow_remote).then(|| "OpenAI URL resolves to a public address.".to_owned()))
        })
    }
    fn record_risk_acknowledgement<'a>(
        &'a self,
        by: &'a str,
        at: OffsetDateTime,
    ) -> BoxFuture<'a, Result<(), CollaboratorError>> {
        Box::pin(async move {
            self.acknowledged.lock().unwrap().push(format!("by {by} at {}", at.unix_timestamp()));
            Ok(())
        })
    }
    fn clear_risk_acknowledgement(&self) -> BoxFuture<'_, Result<(), CollaboratorError>> {
        Box::pin(async move {
            self.acknowledged.lock().unwrap().push("cleared".to_owned());
            Ok(())
        })
    }
}

/// What the SIEM would hear: the signal each entry carries.
#[derive(Default)]
struct Signals(Mutex<Vec<Option<Signal>>>);

impl Listener for Signals {
    fn recorded_in_transaction<'a>(
        &'a self,
        entry: &'a Record,
        _at: OffsetDateTime,
        _tx: &'a mut Tx,
    ) -> BoxFuture<'a, Result<(), ListenerError>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(entry.signal);
            Ok(())
        })
    }
    fn recorded<'a>(&'a self, entry: &'a Record, _at: OffsetDateTime) -> BoxFuture<'a, Result<(), ListenerError>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(entry.signal);
            Ok(())
        })
    }
    fn name(&self) -> &str {
        "Signals"
    }
}

struct Fixture {
    _server: Migrated,
    db: Db,
    settings: Settings,
    audit: AuditLog,
    service: SettingsAdministration,
    people: Arc<People>,
    model: Arc<Model>,
    signals: Arc<Signals>,
}

impl Fixture {
    async fn start(engine: Engine) -> Fixture {
        let server = Migrated::start(engine).await;
        let db = server.connect().await;
        let signals = Arc::new(Signals::default());
        let audit = AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(FixedClock), vec![signals.clone()]);
        let people = Arc::new(People {
            approver: AtomicBool::new(true),
            publishers: AtomicBool::new(true),
            signers: AtomicBool::new(true),
        });
        let model = Arc::new(Model::default());
        let service = SettingsAdministration::new(
            db.clone(),
            audit.clone(),
            people.clone(),
            Arc::new(Pins),
            model.clone(),
            Arc::new(FixedClock),
        );
        Fixture { _server: server, settings: Settings::new(db.clone()), db, audit, service, people, model, signals }
    }

    async fn entries(&self) -> Vec<StoredEntry> {
        let mut all = self.audit.recent(1_000).await.unwrap();
        all.reverse();
        all
    }

    async fn save(&self, body: &[(&str, Option<&str>)], writer: &Caller) -> Result<Applied, AdministrationError> {
        let body: Vec<(String, Option<String>)> =
            body.iter().map(|(key, value)| ((*key).to_owned(), value.map(str::to_owned))).collect();
        self.service.update(&body, Some(writer), &actor(writer)).await
    }

    /// A refusal: its words, and nothing written — no setting, no audit entry.
    async fn refused(&self, body: &[(&str, Option<&str>)], writer: &Caller) -> AdministrationError {
        let before = (self.settings.stored().await.unwrap(), self.entries().await.len());
        let refusal = self.save(body, writer).await.expect_err("refused");
        assert_eq!((self.settings.stored().await.unwrap(), self.entries().await.len()), before, "{refusal}");
        refusal
    }
}

fn caller(name: &str, administrative: bool, governs_platform: bool) -> Caller {
    Caller { username: name.to_owned(), administrative, governs_platform }
}

fn actor(writer: &Caller) -> RequestActor {
    RequestActor {
        username: Some(writer.username.clone()),
        ip_address: Some("203.0.113.9".to_owned()),
        user_agent: Some("settings-test".to_owned()),
    }
}

fn invalid(refusal: AdministrationError) -> String {
    match refusal {
        AdministrationError::InvalidInput(words) => words,
        other => panic!("expected a 400, got {other:?}"),
    }
}

fn denied(refusal: AdministrationError) -> String {
    match refusal {
        AdministrationError::AccessDenied(words) => words,
        other => panic!("expected a 403, got {other:?}"),
    }
}

/// The catalog as each reader sees it, a save written and audited in order, and the SOC told only when a setting
/// that decides what the deployment protects was among it.
async fn the_catalog_and_a_save(engine: Engine) {
    let f = Fixture::start(engine).await;
    let admin = caller("admin", true, false);
    let lead = caller("lead", false, false);

    let mut tx = f.db.begin(vectispire_cp_db::Mode::ReadWrite).await.unwrap();
    f.settings.set(&mut tx, Setting::WebhookUrl, "https://hooks.example/team").await.unwrap();
    f.settings.set(&mut tx, Setting::TicketToken, "ciphertext").await.unwrap();
    tx.commit().await.unwrap();
    for (reader, sees_secret) in [(Some(&admin), true), (Some(&lead), false), (None, false)] {
        let catalog = f.service.catalog(reader).await.unwrap();
        assert_eq!(catalog.len(), Setting::ALL.len());
        let entry = |setting| catalog.iter().find(|entry| entry.setting == setting).unwrap();
        assert_eq!(
            entry(Setting::WebhookUrl).value.as_deref(),
            sees_secret.then_some("https://hooks.example/team"),
            "a sensitive value leaves for an administrator only"
        );
        assert!(entry(Setting::WebhookUrl).configured);
        assert_eq!(entry(Setting::TicketToken).value, None, "a credential leaves for nobody");
        assert!(entry(Setting::TicketToken).configured, "but whether one is set is said");
        assert_eq!(entry(Setting::SlaHighDays).value.as_deref(), Some("30"), "the default, absent a row");
        assert!(!entry(Setting::SlaHighDays).configured);
        assert!(entry(Setting::TargetVisibility).governor_only && !entry(Setting::TargetVisibility).administrator_only);
        assert!(entry(Setting::TicketBaseUrl).administrator_only && !entry(Setting::TicketBaseUrl).governor_only);
    }

    // A plain save: trimmed values, the keys in the request's order, the empty value named, nothing signalled.
    let applied = f
        .save(&[("sla_high_days", Some(" 45 ")), ("license_blocklist", None), ("sast_enabled", Some("true"))], &lead)
        .await
        .unwrap();
    assert_eq!(
        applied,
        Applied {
            count: 3,
            keys: "sla_high_days,license_blocklist,sast_enabled".to_owned(),
            description: "sla_high_days = 45; license_blocklist = (empty); sast_enabled = true".to_owned(),
        }
    );
    assert_eq!(f.settings.get(Setting::SlaHighDays).await.unwrap(), "45");
    assert!(f.settings.is_stored(Setting::LicenseBlocklist).await.unwrap(), "null is saved as empty");
    let entries = f.entries().await;
    let last = entries.last().unwrap();
    assert_eq!(
        (last.operation_type.as_str(), last.resource_id.as_str(), last.description.as_str()),
        ("SETTING_UPDATED", applied.keys.as_str(), applied.description.as_str())
    );
    assert_eq!(
        (last.user_id.as_deref(), last.ip_address.as_deref(), last.user_agent.as_deref()),
        (Some("lead"), Some("203.0.113.9"), Some("settings-test")),
        "the actor's identity"
    );
    assert_eq!(f.signals.0.lock().unwrap().last().copied(), Some(None), "retention and SLAs stay out of a SOC's feed");

    // A secret's value stays out of the entry; four-eyes is said in words; a security setting is signalled.
    let governor = caller("governor", true, true);
    let applied = f
        .save(
            &[
                ("notification_slack_url", Some("https://hooks.slack.example/x")),
                ("notification_teams_url", Some("")),
                ("triage_four_eyes_required", Some("false")),
            ],
            &governor,
        )
        .await
        .unwrap();
    assert_eq!(
        applied.description,
        "notification_slack_url changed; notification_teams_url cleared; \
         Double validation (Four-Eyes Approval) for VEX triage set to DISABLED"
    );
    assert_eq!(f.signals.0.lock().unwrap().last().copied(), Some(Some(SECURITY_SETTING_CHANGED)));
    let applied = f.save(&[("triage_four_eyes_required", Some("true"))], &governor).await.unwrap();
    assert_eq!(applied.description, "Double validation (Four-Eyes Approval) for VEX triage set to ENABLED");
    assert_eq!(f.entries().await.len(), 3, "one entry per save");
    assert_eq!(f.model.acknowledged.lock().unwrap().len(), 0, "the switch was not touched");
}

/// Every refusal of a save, in Java's words and in Java's order, and nothing written by any of them.
async fn every_refusal(engine: Engine) {
    let f = Fixture::start(engine).await;
    let admin = caller("admin", true, false);
    let lead = caller("lead", false, false);
    let governor = caller("governor", true, true);

    assert_eq!(invalid(f.refused(&[], &admin).await), "No setting supplied.");
    assert_eq!(
        invalid(f.refused(&[("sla_high_days", Some("40")), ("no_such_key", Some("x"))], &admin).await),
        "Unknown setting: \"no_such_key\".",
        "all validated before any is written"
    );
    assert_eq!(
        invalid(f.refused(&[("ai_review_risk_acknowledged_by", Some("me"))], &governor).await),
        "Data-leak risk accepted by is recorded by the server when the public endpoint is turned on, and cannot be \
         set here."
    );
    assert_eq!(
        invalid(f.refused(&[("ai_review_risk_acknowledged_at", Some("2026-10-17"))], &governor).await),
        "Data-leak risk accepted on is recorded by the server when the public endpoint is turned on, and cannot be \
         set here."
    );

    // Governor-only: an administrator is refused, the governor is not.
    for setting in
        ["target_visibility", "triage_four_eyes_required", "checklist_auto_answer", "evidence_retention_days"]
    {
        let label = Setting::by_key(setting).unwrap().label();
        assert_eq!(
            denied(f.refused(&[(setting, Some("1"))], &admin).await),
            format!(
                "{label} decides a rule rather than a setting: only a platform governor may change it, because it is \
                 the one role that cannot act under it."
            )
        );
    }

    // Administrator-only, on a change only: the value sent back unchanged passes.
    assert_eq!(
        denied(f.refused(&[("ticket_base_url", Some("https://tracker.example"))], &lead).await),
        "Tracker URL decides where access token is sent, and only an administrator — who alone may set that \
         credential — may change it."
    );
    assert_eq!(
        denied(f.refused(&[("ai_review_allow_remote_url", Some("true"))], &lead).await),
        "Allow a public model endpoint decides where openai api key is sent, and only an administrator — who alone \
         may set that credential — may change it."
    );
    assert_eq!(
        denied(f.refused(&[("ticket_token_expires_on", Some("2027-01-31"))], &lead).await),
        "Token expiry date describes the tracker token, which only an administrator sets, and only an administrator \
         may change it."
    );
    assert_eq!(
        denied(f.refused(&[("siem_allow_private_destination", Some("true"))], &lead).await),
        "Allow a private SIEM destination decides how far a channel configured by a security lead may reach, and \
         only an administrator may change it."
    );
    f.save(&[("ticket_base_url", Some("")), ("ticket_allow_private_url", Some(" true "))], &lead)
        .await
        .expect("the stored values sent back unchanged, trimmed");

    // Four-eyes on needs people to honour it, each check in turn; off needs nobody.
    f.people.approver.store(false, Ordering::SeqCst);
    assert_eq!(
        invalid(f.refused(&[("triage_four_eyes_required", Some("TRUE"))], &governor).await),
        "No active account can approve a triage: switching four-eyes on would put every decision in a queue nobody \
         can empty. Create an administrator, a CISO or a security lead first."
    );
    f.save(&[("triage_four_eyes_required", Some("false"))], &governor).await.expect("off needs nobody");
    f.people.approver.store(true, Ordering::SeqCst);
    f.people.publishers.store(false, Ordering::SeqCst);
    assert_eq!(
        invalid(f.refused(&[("triage_four_eyes_required", Some("1"))], &governor).await),
        "Fewer than two active accounts can publish a checklist template: under four-eyes its author may not \
         publish it, so no draft could ever be published. Create a second platform governor, administrator or CISO \
         first."
    );
    f.people.publishers.store(true, Ordering::SeqCst);
    f.people.signers.store(false, Ordering::SeqCst);
    assert_eq!(
        invalid(f.refused(&[("triage_four_eyes_required", Some("true"))], &governor).await),
        "Fewer than two active accounts can sign off a project checklist: under four-eyes none of its authors may \
         sign it off, so a checklist its only approver filled in could never be signed off. Create a second \
         administrator, CISO or security champion first."
    );
    f.people.signers.store(true, Ordering::SeqCst);

    // A credential has its own door.
    for (setting, label) in [
        ("ticket_token", "Access token"),
        ("notification_webhook_secret", "Webhook signing secret"),
        ("ai_review_openai_key", "OpenAI API key"),
        ("ticket_webhook_secret", "Inbound webhook secret"),
    ] {
        assert_eq!(
            invalid(f.refused(&[(setting, Some("s3cr3t"))], &admin).await),
            format!(
                "{label} is a credential and is written by its own route, which encrypts it. Setting it here would \
                 store it in the clear."
            )
        );
    }

    // The type's own words, after the label.
    assert_eq!(
        invalid(f.refused(&[("sast_enabled", Some("yes"))], &admin).await),
        "Analyze the code with Semgrep — Expected value: \"true\" or \"false\"."
    );

    // The tracker's CA, on a change only; the token's expiry, a date.
    assert_eq!(
        invalid(f.refused(&[("ticket_ca_pem", Some("-----BEGIN NOT A CA-----"))], &admin).await),
        "Tracker CA (PEM) — not a CA certificate."
    );
    // One stored before, and since become unpinnable, sent back unchanged with the section: the calls' to refuse.
    let mut tx = f.db.begin(vectispire_cp_db::Mode::ReadWrite).await.unwrap();
    f.settings.set(&mut tx, Setting::TicketCa, "-----BEGIN NOT A CA-----\n").await.unwrap();
    tx.commit().await.unwrap();
    f.save(&[("ticket_ca_pem", Some("-----BEGIN NOT A CA-----"))], &admin).await.expect("unchanged, once trimmed");
    assert_eq!(
        invalid(f.refused(&[("ticket_token_expires_on", Some("2027-02-30"))], &admin).await),
        "Token expiry date — a date, written as 2027-01-31."
    );
    f.save(&[("ticket_token_expires_on", Some("2027-02-28"))], &admin).await.expect("a date");

    // A GitHub project is owner/repository — checked on the state the save produces, and only on a change.
    let github = "Project — a GitHub repository is \"owner/repository\": letters, digits and hyphens for the owner, \
                  letters, digits, dots, underscores and hyphens for the repository, and nothing after it.";
    assert_eq!(
        invalid(f.refused(&[("ticket_provider", Some("GitHub")), ("ticket_project", Some("acme"))], &admin).await),
        github
    );
    let mut tx = f.db.begin(vectispire_cp_db::Mode::ReadWrite).await.unwrap();
    f.settings.set(&mut tx, Setting::TicketProject, "acme/../x").await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(invalid(f.refused(&[("ticket_provider", Some("github"))], &admin).await), github, "the stored project");
    f.save(&[("ticket_provider", Some("gitlab"))], &admin).await.expect("not GitHub");
    f.save(&[("ticket_provider", Some("github")), ("ticket_project", Some("acme/vectispire"))], &admin)
        .await
        .expect("a repository");
    f.save(&[("ticket_labels", Some("security"))], &admin).await.expect("the GitHub settings untouched");
    f.save(&[("ticket_project", Some(" "))], &admin).await.expect("no project is not a malformed one");
    // A project stored before the check, not `owner/repository`, under GitHub: refused at the send, not here.
    let mut tx = f.db.begin(vectispire_cp_db::Mode::ReadWrite).await.unwrap();
    f.settings.set(&mut tx, Setting::TicketProject, "legacy project").await.unwrap();
    tx.commit().await.unwrap();
    f.save(&[("ticket_labels", Some("vectispire"))], &admin).await.expect("neither the provider nor the project moved");
    f.save(&[("ticket_provider", Some("github"))], &admin).await.expect("the provider sent back unchanged");
}

/// The AI destination is judged on the state the save produces, a save that withdraws the acknowledgement is never
/// refused, and the acknowledgement is stamped or erased on the switch's transition only.
async fn the_ai_destination_and_its_acknowledgement(engine: Engine) {
    let f = Fixture::start(engine).await;
    let admin = caller("admin", true, false);

    assert_eq!(
        match f.refused(&[("ai_review_provider", Some("openai"))], &admin).await {
            AdministrationError::UnsafeUrl(words) => words,
            other => panic!("{other:?}"),
        },
        "OpenAI URL resolves to a public address."
    );
    assert_eq!(f.model.asked.lock().unwrap().last().unwrap(), "openai None None false", "the provider this save sets");
    f.save(
        &[("ai_review_provider", Some("openai")), ("ai_review_openai_url", Some("https://internal.example/v1"))],
        &admin,
    )
    .await
    .expect("an internal endpoint");
    assert_eq!(
        f.model.asked.lock().unwrap().last().unwrap(),
        "openai Some(\"https://internal.example/v1\") None false",
        "the URL this save sets"
    );

    // Turned on: stamped by the server, with the writer's name and the clock's instant.
    f.save(
        &[("ai_review_openai_url", Some("https://api.openai.com/v1")), ("ai_review_allow_remote_url", Some("true"))],
        &admin,
    )
    .await
    .unwrap();
    assert_eq!(*f.model.acknowledged.lock().unwrap(), vec![format!("by admin at {AT}")]);
    // Saved again unchanged, with something else: not stamped again.
    f.save(&[("ai_review_allow_remote_url", Some("true")), ("ai_review_model", Some("gpt-x"))], &admin).await.unwrap();
    assert_eq!(f.model.acknowledged.lock().unwrap().len(), 1, "only on the transition");

    // Withdrawn while the provider still points off-site: never refused, and the record erased.
    let asked = f.model.asked.lock().unwrap().len();
    f.save(&[("ai_review_allow_remote_url", Some("false"))], &admin).await.expect("a safer configuration");
    assert_eq!(f.model.asked.lock().unwrap().len(), asked, "the guard is not asked about a withdrawal");
    assert_eq!(f.model.acknowledged.lock().unwrap().last().unwrap(), "cleared");
    assert_eq!(f.settings.get(Setting::AiReviewAllowRemote).await.unwrap(), "false");
}

macro_rules! on_both_engines {
    ($($name:ident),* $(,)?) => {
        mod mysql {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { if vectispire_cp_db::testing::runs_on(super::Engine::MySql) { super::$name(super::Engine::MySql).await; } })*
        }
        mod postgres {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { if vectispire_cp_db::testing::runs_on(super::Engine::PostgreSql) { super::$name(super::Engine::PostgreSql).await; } })*
        }
    };
}

on_both_engines!(the_catalog_and_a_save, every_refusal, the_ai_destination_and_its_acknowledgement);

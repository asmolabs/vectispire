//! A settings save answers what Java answers: `reference/platform/settings-save.json`, written by
//! `SettingsSaveReferenceSetTest` with the real `SettingsAdministrationService`, the real `AiReviewService` over a real
//! `OutboundUrlGuard`, and `PinnedCa` itself for the tracker CA.
//!
//! Each case puts its rows and its switches in a real database, then saves through [`SettingsAdministration`] composed
//! with the seams the binary composes — [`TrackerCaPinning`] and [`GuardedAiDestination`], over a guard resolving the
//! reference's fixed table — and reads back the refusal (its status, its words, the integration a 409 names) or the
//! answer and the audit entry, and every stored row. On the engines `VECTISPIRE_TEST_ENGINES` selects.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use support::Migrated;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use vectispire_cp_audit::{AuditLog, Clock, Listener, ListenerError, NoMirror, Record, RequestActor};
use vectispire_cp_db::{Db, Tx};
use vectispire_cp_outbound::OutboundUrlGuard;
use vectispire_cp_outbound::address::Raw;
use vectispire_cp_platform::{
    AdministrationError, AiEndpoint, Approvers, Caller, CollaboratorError, GuardedAiDestination,
    SettingsAdministration, SettingsParts, TrackerCaPinning,
};
use vectispire_cp_settings::{Integrations, Settings};
use vectispire_domain::integrations::Integration;

fn reference() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/platform/settings-save.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("the reference set is committed"))
        .expect("the reference set is JSON")
}

#[derive(Debug)]
struct Fixed(OffsetDateTime);

impl Clock for Fixed {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// `access`' three answers, as the case sets them.
struct People(Value);

impl Approvers for People {
    fn any_active(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>> {
        Box::pin(async move { Ok(self.0["approver"].as_bool().unwrap()) })
    }
    fn two_can_publish_templates(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>> {
        Box::pin(async move { Ok(self.0["publishers"].as_bool().unwrap()) })
    }
    fn two_can_sign_off_checklists(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>> {
        Box::pin(async move { Ok(self.0["signers"].as_bool().unwrap()) })
    }
}

/// The endpoint check is not what a save asks.
struct NoEndpoint;

impl AiEndpoint for NoEndpoint {
    fn provider(&self) -> BoxFuture<'_, Result<String, CollaboratorError>> {
        unreachable!("a save does not check the endpoint")
    }
    fn selected_model(&self) -> BoxFuture<'_, Result<String, CollaboratorError>> {
        unreachable!("a save does not check the endpoint")
    }
    fn allow_remote(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>> {
        unreachable!("a save does not check the endpoint")
    }
    fn validated_url(&self) -> BoxFuture<'_, Result<Result<String, String>, CollaboratorError>> {
        unreachable!("a save does not check the endpoint")
    }
    fn base_url(&self) -> BoxFuture<'_, Result<String, CollaboratorError>> {
        unreachable!("a save does not check the endpoint")
    }
    fn has_openai_key(&self) -> BoxFuture<'_, Result<bool, CollaboratorError>> {
        unreachable!("a save does not check the endpoint")
    }
    fn available_models(&self) -> BoxFuture<'_, Result<Option<Vec<String>>, CollaboratorError>> {
        unreachable!("a save does not check the endpoint")
    }
}

/// Every entry recorded, with the signal the SIEM would hear.
#[derive(Default)]
struct Entries(Mutex<Vec<Record>>);

impl Listener for Entries {
    fn recorded_in_transaction<'a>(
        &'a self,
        entry: &'a Record,
        _at: OffsetDateTime,
        _tx: &'a mut Tx,
    ) -> BoxFuture<'a, Result<(), ListenerError>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(entry.clone());
            Ok(())
        })
    }
    fn recorded<'a>(&'a self, entry: &'a Record, _at: OffsetDateTime) -> BoxFuture<'a, Result<(), ListenerError>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(entry.clone());
            Ok(())
        })
    }
    fn name(&self) -> &str {
        "Entries"
    }
}

fn guard(table: &Value) -> OutboundUrlGuard {
    let table: BTreeMap<String, Vec<Raw>> = table
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, hex)| {
            let hex = hex.as_str().unwrap();
            let bytes: Vec<u8> =
                (0..hex.len()).step_by(2).map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap()).collect();
            (name.clone(), vec![Raw::V4(bytes.try_into().unwrap())])
        })
        .collect();
    OutboundUrlGuard::with_resolver(
        move |hostname: &str| table.get(&hostname.to_lowercase()).cloned().unwrap_or_default(),
        Vec::new(),
    )
}

/// `Role.of(role)`'s two properties, as `cp-http` holds the roles.
fn writer(role: &Value) -> Option<Caller> {
    let role = vectispire_cp_http::principal::Role::parse(role.as_str()?).expect("a role Java knows");
    Some(Caller {
        username: "  lead\t".to_owned(),
        administrative: role.is_administrative(),
        governs_platform: role.governs_platform(),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_save_answers_what_java_answers() {
    for engine in vectispire_cp_db::testing::engines() {
        if !vectispire_cp_db::testing::runs_on(*engine) {
            continue;
        }
        let migrated = Arc::new(Migrated::start(*engine).await);
        let db = migrated.connect().await;
        let reference = reference();
        let now = OffsetDateTime::parse(reference["now"].as_str().unwrap(), &Rfc3339).unwrap();
        let cases = reference["cases"].as_array().unwrap();
        assert!(cases.len() > 80, "the reference set holds every case");
        let mut differences = Vec::new();
        for case in cases {
            if let Some(difference) = run(&migrated, &db, now, &reference["resolver"], case).await {
                differences.push(difference);
            }
        }
        db.close().await;
        assert!(
            differences.is_empty(),
            "{engine:?}: {} of {} cases differ:\n{}",
            differences.len(),
            cases.len(),
            differences.join("\n")
        );
    }
}

async fn run(migrated: &Arc<Migrated>, db: &Db, now: OffsetDateTime, resolver: &Value, case: &Value) -> Option<String> {
    let name = case["name"].as_str().unwrap();
    // The rows before the save, and nothing else: no default a migration seeded, nothing a case before left.
    let admin = migrated.clone();
    tokio::task::spawn_blocking(move || admin.sql_as_admin("delete from t_setting")).await.unwrap();
    let settings = Settings::new(db.clone());
    let mut tx = db.begin(vectispire_cp_db::Mode::ReadWrite).await.unwrap();
    for (key, value) in case["prior"].as_object().unwrap() {
        let setting = vectispire_cp_settings::Setting::by_key(key).unwrap();
        settings.set(&mut tx, setting, value.as_str().unwrap()).await.unwrap();
    }
    tx.commit().await.unwrap();

    let integrations = Integrations::new(db.clone(), Vec::new(), Arc::new(move || now));
    let disabled: Vec<Integration> = case["disabled"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| Integration::by_key(key.as_str().unwrap()).unwrap())
        .collect();
    for integration in &disabled {
        integrations.switch_to(*integration, false, "governor").await.unwrap();
    }

    let entries = Arc::new(Entries::default());
    let clock = Arc::new(Fixed(now));
    let audit = AuditLog::new(db.clone(), Arc::new(NoMirror), clock.clone(), vec![entries.clone()]);
    let service = SettingsAdministration::new(SettingsParts {
        db: db.clone(),
        audit,
        approvers: Arc::new(People(case["people"].clone())),
        tracker: Arc::new(TrackerCaPinning::new(clock.clone())),
        ai: Arc::new(GuardedAiDestination::new(settings.clone(), guard(resolver))),
        endpoint: Arc::new(NoEndpoint),
        integrations: integrations.clone(),
        clock,
    });
    let body: Vec<(String, Option<String>)> = case["body"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| (pair[0].as_str().unwrap().to_owned(), pair[1].as_str().map(str::to_owned)))
        .collect();
    let actor = RequestActor {
        username: Some("admin".to_owned()),
        ip_address: Some("203.0.113.7".to_owned()),
        user_agent: Some("reference".to_owned()),
    };
    let answered = service.update(&body, writer(&case["role"]).as_ref(), &actor).await;

    let mut outcome = serde_json::Map::new();
    match answered {
        Ok(applied) => {
            outcome.insert("updated".into(), json!(applied.count));
        }
        Err(refused) => {
            let (status, integration) = match &refused {
                AdministrationError::InvalidInput(_) => (400, None),
                AdministrationError::AccessDenied(_) => (403, None),
                AdministrationError::IntegrationDisabled { integration, .. } => (409, Some(integration.key())),
                AdministrationError::UnsafeUrl(_) => (422, None),
                failure => return Some(format!("{name}: failed: {failure}")),
            };
            outcome.insert(
                "refused".into(),
                json!({ "status": status, "detail": refused.to_string(), "integration": integration }),
            );
        }
    }
    let audited: Vec<Value> = entries
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|entry| {
            json!({
                "operation": entry.operation.wire_name(),
                "resourceId": entry.resource_id,
                "description": entry.description,
                "userId": entry.user_id,
                "signal": entry.signal.map(|signal| signal.0),
            })
        })
        .collect();
    outcome.insert("audit".into(), Value::Array(audited));
    let stored = settings.stored().await.unwrap();
    outcome.insert("stored".into(), json!(stored));

    for integration in &disabled {
        integrations.switch_to(*integration, true, "governor").await.unwrap();
    }
    let outcome = Value::Object(outcome);
    (outcome != case["outcome"]).then(|| format!("{name}:\n  java: {}\n  rust: {}", case["outcome"], outcome))
}

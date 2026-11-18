//! The notifications on real servers: what keeps a channel in use (Java's `NotificationChannelSwitchRoutesTest`), what a
//! settings save configures, the routing of a scan's delta into outbox rows (`TeamNotificationRoutingTest`,
//! `ProjectNotificationRoutingTest`), a token's alert queued per channel (`TokenAlertChannelsTest`), and a delivery to a
//! switched-off channel held, to a vanished team gone (`NotificationServiceTest`).
//!
//! **Docker is required, and its absence fails the test.**
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

use std::collections::HashMap;
use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine, Mode, ScanTarget};
use vectispire_cp_issues::{IssueView, ScanDelta};
use vectispire_cp_notifications::routing::TargetDirectory;
use vectispire_cp_notifications::{
    Channels, NotificationChannelInUse, NotificationDestinations, NotificationError, NotificationTestService,
    NotificationsConfig, ScanDeltaNotifier, TokenAlerts,
};
use vectispire_cp_outbound::{OutboundPost, OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_outbox::{DeliveryError, NotificationChannel, Outbox, Registry, TokenAlertSink};
use vectispire_cp_settings::{InUse, Integrations, Setting, Settings};
use vectispire_domain::instant::Instant;
use vectispire_domain::integrations::Integration;
use vectispire_domain::notifications::{Credential, Notice, NotificationChannelKind, TokenAlert};
use vectispire_domain::secret::Secret;

const KEY: &str = "cmVmZXJlbmNlLXNjYW5uaW5nLWtleS0zMi1ieXRlcyE="; // gitleaks:allow — test fixture
const REPO: i64 = 301;
const PROJECT: i64 = 41;

#[test]
fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    run(Engine::MySql);
}

#[test]
fn on_postgresql() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    run(Engine::PostgreSql);
}

type Check = Result<(), String>;

macro_rules! ensure_eq {
    ($left:expr, $right:expr, $($what:tt)+) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(format!("{}: {:?} != {:?}", format!($($what)+), left, right));
        }
    }};
}

struct World {
    server: TestDatabase,
    db: Db,
    config: NotificationsConfig,
    channels: Channels,
}

fn config(db: &Db) -> NotificationsConfig {
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    let encryption = EncryptionConfig { key: Some(Secret::new(KEY)), ..EncryptionConfig::default() };
    NotificationsConfig {
        db: db.clone(),
        settings: Settings::new(db.clone()),
        integrations: Integrations::new(
            db.clone(),
            vec![Arc::new(NotificationChannelInUse::new(NotificationDestinations::new(Settings::new(db.clone()))))],
            Arc::new(OffsetDateTime::now_utc),
        ),
        encryption: Arc::new(Encryption::new(&encryption, door).unwrap()),
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

fn run(engine: Engine) {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = TestDatabase::start(engine).await;
        let overriding = if engine == Engine::PostgreSql { " overriding system value" } else { "" };
        let at = if engine == Engine::PostgreSql { "'2026-01-01 00:00:00+00'" } else { "'2026-01-01 00:00:00'" };
        server.sql_as_admin(&format!(
            "insert into t_solution (id, name, created_at){overriding} values (1, 'Sol', {at})"
        ));
        server.sql_as_admin(&format!(
            "insert into t_project (id, solution_id, name, created_at){overriding} values ({PROJECT}, 1, 'Proj', {at})"
        ));
        server.sql_as_admin(&format!(
            "insert into t_repository (id, url, branch, name, project_id){overriding} values ({REPO}, \
             'https://forge.example/web.git', 'main', 'web', {PROJECT})"
        ));
        for (id, name) in [(1, 'a'), (2, 'b'), (3, 'c')] {
            server.sql_as_admin(&format!(
                "insert into t_team (id, name, created_at){overriding} values ({id}, '{name}', {at})"
            ));
        }
        let db = server.connect().await;
        let config = config(&db);
        let channels = vectispire_cp_notifications::channels(&config);
        let world = World { server, db, config, channels };
        let mut failures = Vec::new();
        macro_rules! each {
            ($($check:ident),* $(,)?) => {$(
                world.server.sql_as_admin("delete from t_outbox_message");
                world.server.sql_as_admin("delete from t_team_webhook");
                world.server.sql_as_admin("delete from t_team_target");
                world.server.sql_as_admin("delete from t_setting");
                world.server.sql_as_admin("update t_integration set enabled = true where integration_key like 'notification.%'");
                if let Err(failure) = $check(&world).await {
                    failures.push(format!("{}: {failure}", stringify!($check)));
                }
            )*};
        }
        each!(
            a_channel_with_a_destination_is_in_use,
            a_save_configures_what_it_changes,
            a_delta_is_queued_once_per_listening_channel,
            an_owning_team_is_told_through_its_project_too,
            nothing_notable_queues_nothing,
            a_token_alert_is_queued_for_its_audit_and_each_channel,
            a_switched_off_channel_holds_and_a_vanished_team_is_gone,
            the_test_button_refuses_in_java_s_order,
        );
        world.db.close().await;
        assert!(failures.is_empty(), "{engine}: {} check(s) failed:\n  {}", failures.len(), failures.join("\n  "));
    });
}

async fn set(world: &World, setting: Setting, value: &str) {
    let mut tx = world.db.begin(Mode::ReadWrite).await.unwrap();
    world.config.settings.set(&mut tx, setting, value).await.unwrap();
    tx.commit().await.unwrap();
}

async fn switch(world: &World, kind: NotificationChannelKind, on: bool) {
    world.config.integrations.switch_to(kind.integration(), on, "governor").await.unwrap();
}

fn rows(world: &World) -> Vec<(String, Option<i64>)> {
    world
        .server
        .sql_as_admin("select message_type, coalesce(team_id, -1) from t_outbox_message order by message_type, team_id")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut parts = line.split('\t');
            let kind = parts.next().unwrap().trim().to_owned();
            let team: i64 = parts.next().unwrap().trim().parse().unwrap();
            (kind, (team >= 0).then_some(team))
        })
        .collect()
}

async fn in_use(world: &World, kind: NotificationChannelKind) -> Option<String> {
    let probe = NotificationChannelInUse::new(NotificationDestinations::new(world.config.settings.clone()));
    let mut tx = world.db.begin(Mode::ReadOnly).await.unwrap();
    let answer = probe.in_use(&mut tx, kind.integration()).await.unwrap();
    tx.commit().await.unwrap();
    answer
}

async fn a_channel_with_a_destination_is_in_use(world: &World) -> Check {
    ensure_eq!(in_use(world, NotificationChannelKind::Webhook).await, None, "nothing set");
    set(world, Setting::WebhookUrl, "https://hooks.example/a").await;
    world.server.sql_as_admin("insert into t_team_webhook (team_id, url) values (1, 'https://t.example/1')");
    world.server.sql_as_admin("insert into t_team_webhook (team_id, url) values (2, 'https://t.example/2')");
    ensure_eq!(
        in_use(world, NotificationChannelKind::Webhook).await,
        Some(
            "it is a channel the alerts are sent to — the global webhook URL is set, 2 teams have a webhook of their \
             own. Empty it first, in the notification settings or on the team: the alerts queued for it would \
             otherwise have nowhere to go, and be lost in silence."
                .to_owned()
        ),
        "the global URL and the teams'"
    );
    // Teams needs its switch as well as its URL, as it does to send.
    set(world, Setting::TeamsEnabled, "false").await;
    set(world, Setting::TeamsWebhookUrl, "https://teams.example/a").await;
    ensure_eq!(in_use(world, NotificationChannelKind::Teams).await, None, "a Teams URL without its switch");
    set(world, Setting::ChecklistRemindersEnabled, "true").await;
    let mail = in_use(world, NotificationChannelKind::Mail).await.unwrap_or_default();
    if !mail.contains("the weekly checklist reminders are on") {
        return Err(format!("mail: {mail}"));
    }
    // The registry asks it, and refuses the switch with it.
    let refused = world.config.integrations.switch_to(NotificationChannelKind::Webhook.integration(), false, "g").await;
    if !matches!(refused, Err(vectispire_cp_settings::IntegrationsError::InUse(..))) {
        return Err(format!("the switch-off was not refused: {refused:?}"));
    }
    let probe = NotificationChannelInUse::new(NotificationDestinations::new(world.config.settings.clone()));
    let mut tx = world.db.begin(Mode::ReadOnly).await.unwrap();
    let siem = probe.in_use(&mut tx, Integration::by_key("siem.webhook").unwrap()).await.unwrap();
    tx.commit().await.unwrap();
    ensure_eq!(siem, None, "another family");
    Ok(())
}

async fn a_save_configures_what_it_changes(world: &World) -> Check {
    let destinations = NotificationDestinations::new(world.config.settings.clone());
    set(world, Setting::ChecklistRemindersEnabled, "true").await;
    // A webhook URL is a secret: sent, it configures, whatever is stored — a guess is never compared.
    set(world, Setting::DiscordWebhookUrl, "https://discord.example/b").await;
    let changes: HashMap<Setting, String> = [
        (Setting::ChecklistRemindersEnabled, "true".to_owned()),
        (Setting::DiscordWebhookUrl, "https://discord.example/b".to_owned()),
        (Setting::TeamsEnabled, "false".to_owned()),
        (Setting::MailRecipients, String::new()),
    ]
    .into();
    ensure_eq!(
        destinations.configured_by(&changes).await.map_err(|e| e.to_string())?,
        vec![NotificationChannelKind::Discord],
        "the stored switch sent back, a switch off and a cleared list configure nothing; a secret always does"
    );
    Ok(())
}

fn issue(id: i64, severity: &str, kind: &str) -> IssueView {
    serde_json::from_value(serde_json::json!({
        "id": id, "repoId": REPO, "fingerprint": format!("f{id}"), "type": kind, "identifier": format!("CVE-{id}"),
        "severity": severity, "isKev": false, "state": "open", "firstSeenAt": "2026-01-01T00:00:00Z",
        "lastSeenAt": "2026-01-01T00:00:00Z", "timesSeen": 1, "triageStatus": "under_review"
    }))
    .unwrap()
}

fn delta(issues: Vec<IssueView>) -> ScanDelta {
    ScanDelta {
        scan_id: 9,
        target: ScanTarget::Repository(REPO),
        new_issues: issues,
        reopened_issues: Vec::new(),
        resolved: 1,
    }
}

struct Directory;

impl TargetDirectory for Directory {
    fn name_of(
        &self,
        _: ScanTarget,
    ) -> futures_util::future::BoxFuture<'_, Result<String, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async { Ok("web".to_owned()) })
    }
    fn project_of(
        &self,
        _: ScanTarget,
    ) -> futures_util::future::BoxFuture<'_, Result<Option<i64>, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async { Ok(Some(PROJECT)) })
    }
}

fn notifier(world: &World) -> ScanDeltaNotifier {
    ScanDeltaNotifier::new(
        world.channels.service.clone(),
        world.channels.all(),
        Arc::new(Outbox::on_database(
            world.db.clone(),
            Registry::new(Vec::new(), Vec::new()),
            Arc::new(vectispire_cp_maintenance::SystemClock),
        )),
        Arc::new(Directory),
        world.config.integrations.clone(),
    )
}

async fn route(world: &World, delta: &ScanDelta) {
    let mut tx = world.db.begin(Mode::ReadWrite).await.unwrap();
    notifier(world).route(&mut tx, delta).await.unwrap();
    tx.commit().await.unwrap();
}

async fn a_delta_is_queued_once_per_listening_channel(world: &World) -> Check {
    set(world, Setting::SlackWebhookUrl, "https://slack.example/a").await;
    set(world, Setting::DiscordWebhookUrl, "https://discord.example/a").await;
    set(world, Setting::TeamsEnabled, "false").await;
    set(world, Setting::TeamsWebhookUrl, "https://teams.example/a").await;
    // Discord switched off is queued nothing; Teams without its switch is not configured.
    set(world, Setting::DiscordWebhookUrl, "").await;
    switch(world, NotificationChannelKind::Discord, false).await;
    set(world, Setting::DiscordWebhookUrl, "https://discord.example/a").await;
    route(world, &delta(vec![issue(1, "critical", "vulnerability")])).await;
    ensure_eq!(rows(world), vec![("scan_delta_slack".to_owned(), None)], "the rows queued");
    let payload = world.server.sql_as_admin("select payload from t_outbox_message");
    if !payload.contains("\"text\":\"Vectispire — web: 1 new issue(s) (1 resolved)\"") {
        return Err(format!("payload: {payload}"));
    }
    Ok(())
}

async fn an_owning_team_is_told_through_its_project_too(world: &World) -> Check {
    world.server.sql_as_admin(&format!(
        "insert into t_team_target (team_id, target_kind, target_id) values (1, 'project', {PROJECT})"
    ));
    world.server.sql_as_admin(&format!(
        "insert into t_team_target (team_id, target_kind, target_id) values (2, 'repository', {REPO})"
    ));
    world.server.sql_as_admin(&format!(
        "insert into t_team_target (team_id, target_kind, target_id) values (3, 'repository', {REPO})"
    ));
    // Team 3 owns the repository and has no channel: no row whose only future is to be abandoned.
    world.server.sql_as_admin("insert into t_team_webhook (team_id, url) values (1, 'https://t.example/1')");
    world.server.sql_as_admin("insert into t_team_webhook (team_id, url) values (2, 'https://t.example/2')");
    route(world, &delta(vec![issue(1, "high", "vulnerability")])).await;
    ensure_eq!(
        rows(world),
        vec![("scan_delta".to_owned(), Some(1)), ("scan_delta".to_owned(), Some(2))],
        "one copy per owning team with a channel, no global copy without a global URL"
    );
    Ok(())
}

async fn nothing_notable_queues_nothing(world: &World) -> Check {
    set(world, Setting::WebhookUrl, "https://hooks.example/a").await;
    route(world, &delta(vec![issue(1, "critical", "quality"), issue(2, "medium", "vulnerability")])).await;
    ensure_eq!(rows(world), Vec::<(String, Option<i64>)>::new(), "quality never, medium below the threshold");
    Ok(())
}

async fn a_token_alert_is_queued_for_its_audit_and_each_channel(world: &World) -> Check {
    set(world, Setting::WebhookUrl, "https://hooks.example/a").await;
    set(world, Setting::SlackWebhookUrl, "https://slack.example/a").await;
    // Teams configured — its switch and its URL — after the governor switched it off: queued nothing.
    switch(world, NotificationChannelKind::Teams, false).await;
    set(world, Setting::TeamsEnabled, "true").await;
    set(world, Setting::TeamsWebhookUrl, "https://teams.example/a").await;
    let alerts = TokenAlerts::new(
        Arc::new(Outbox::on_database(
            world.db.clone(),
            Registry::new(Vec::new(), Vec::new()),
            Arc::new(vectispire_cp_maintenance::SystemClock),
        )),
        world.channels.all(),
        world.config.integrations.clone(),
    );
    let alert = TokenAlert {
        credential: Credential::TrackerToken,
        reference: Some("ticket_token".into()),
        name: Some("GitLab".into()),
        where_: Some("GitLab".into()),
        notice: Notice::Refused,
        previous: Notice::None,
        expires_at: None,
        refused_status: Some(401),
        refused_since: Some(Instant::of_epoch_second(1_700_000_000)),
        observed_at: Some(Instant::of_epoch_second(1_700_000_000)),
    };
    let mut tx = world.db.begin(Mode::ReadWrite).await.unwrap();
    alerts.changed(&mut tx, &alert).await.unwrap();
    tx.commit().await.unwrap();
    ensure_eq!(
        rows(world),
        vec![
            ("token_alert".to_owned(), None),
            ("token_alert".to_owned(), None),
            ("token_alert_audit".to_owned(), None)
        ],
        "the audit entry and the two configured channels that are on"
    );
    let payloads = world.server.sql_as_admin("select payload from t_outbox_message where message_type = 'token_alert'");
    if !(payloads.contains("\"channel\":\"webhook\"") && payloads.contains("\"channel\":\"slack\"")) {
        return Err(payloads);
    }
    Ok(())
}

async fn a_switched_off_channel_holds_and_a_vanished_team_is_gone(world: &World) -> Check {
    let payload = r#"{"text":"t","target":"web","scan_id":1,"issues":[],"message_id":"m"}"#;
    set(world, Setting::SlackWebhookUrl, "https://slack.example/a").await;
    set(world, Setting::SlackWebhookUrl, "").await;
    switch(world, NotificationChannelKind::Slack, false).await;
    match world.channels.slack.deliver(payload, None).await {
        Err(DeliveryError::Held(reason)) if reason.contains("\"notification.slack\" is disabled") => {}
        other => return Err(format!("slack: {other:?}")),
    }
    match world.channels.webhook.deliver(payload, Some(3)).await {
        Err(DeliveryError::Gone(reason)) => ensure_eq!(
            reason,
            "team 3 no longer has a webhook — deleted, or its channel was cleared".to_owned(),
            "the team's reason"
        ),
        other => return Err(format!("team: {other:?}")),
    }
    match world.channels.webhook.deliver(payload, None).await {
        Err(DeliveryError::Gone(reason)) => {
            ensure_eq!(reason, "the global webhook URL has been cleared".to_owned(), "the global reason");
        }
        other => return Err(format!("global: {other:?}")),
    }
    Ok(())
}

async fn the_test_button_refuses_in_java_s_order(world: &World) -> Check {
    let service = NotificationTestService::new(world.config.clone(), world.channels.all());
    let unknown = service.test_channel("fax").await.map_err(|e| e.to_string())?;
    ensure_eq!(
        (unknown.kind.as_str(), unknown.success, unknown.message.as_str()),
        ("fax", false, "Unknown notification channel type: fax"),
        "an unknown type"
    );
    let unset = service.test_channel("SLACK").await.map_err(|e| e.to_string())?;
    ensure_eq!(
        (unset.kind.as_str(), unset.message.as_str()),
        ("scan_delta_slack", "Channel is not configured with a destination URL/recipient."),
        "a channel with no URL"
    );
    switch(world, NotificationChannelKind::Discord, false).await;
    match service.test_channel("discord").await {
        Err(NotificationError::IntegrationDisabled(integration)) => {
            ensure_eq!(integration.key(), "notification.discord".to_owned(), "the refusal names the channel");
        }
        other => return Err(format!("discord: {other:?}")),
    }
    let listed: Vec<String> =
        service.channels_status().await.map_err(|e| e.to_string())?.into_iter().map(|status| status.kind).collect();
    ensure_eq!(
        listed,
        vec!["scan_delta_mail", "scan_delta", "scan_delta_slack", "scan_delta_teams"],
        "a switched-off channel is not offered"
    );
    Ok(())
}

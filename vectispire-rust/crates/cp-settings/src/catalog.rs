//! The settings catalog — `common.domain.settings.Setting`, every key, in the Java enum's order.
//!
//! **Generated from `reference/settings/catalog.json` by `scripts/generate-catalog.py`**, which the Java side
//! writes (`SettingsReferenceSetTest`); `tests/reference_set.rs` fails while the two disagree. The labels and
//! the help are the screen's words; the rest decides who may write a setting and whether the SOC hears of it.

use crate::types::{Section, Sensitivity, SettingType};

/// A setting the application exposes — and only one a service actually reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Setting {
    EnrichmentEnabled,
    EolEnabled,
    EolWarnDays,
    SastEnabled,
    ScanDefaultIntervalDays,
    RetentionKeepPerTarget,
    RetentionMaxAgeDays,
    EvidenceRetentionDays,
    WebhookUrl,
    TeamsEnabled,
    TeamsWebhookUrl,
    SlackWebhookUrl,
    DiscordWebhookUrl,
    WebhookSigningSecret,
    MailRecipients,
    DigestEnabled,
    ChecklistRemindersEnabled,
    NotificationMinSeverity,
    NotifyOnKev,
    NotificationAllowPrivateUrl,
    SiemAllowPrivateDestination,
    LicenseBlocklist,
    TargetVisibility,
    TicketProvider,
    TicketBaseUrl,
    TicketProject,
    TicketToken,
    TicketWebhookSecret,
    TicketTokenExpiresOn,
    TicketUser,
    TicketIssueType,
    TicketLabels,
    TicketAllowPrivateUrl,
    TicketCa,
    AiReviewEnabled,
    AiReviewOwaspAfterScan,
    AiReviewProvider,
    AiReviewOllamaUrl,
    AiReviewOpenaiUrl,
    AiReviewOpenaiKey,
    AiReviewModel,
    AiReviewTimeoutSeconds,
    AiReviewAllowRemote,
    AiReviewRiskAcknowledgedBy,
    AiReviewRiskAcknowledgedAt,
    ComplianceFreshnessDays,
    IsmsScopeStatement,
    IsmsScopeAssets,
    SlaCriticalDays,
    SlaHighDays,
    SlaMediumDays,
    SlaLowDays,
    FourEyesApprovalRequired,
    ChecklistAutoAnswer,
}

/// What the catalog says of one setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Definition {
    pub key: &'static str,
    pub setting_type: SettingType,
    pub section: Section,
    pub label: &'static str,
    /// What this setting changes, and above all what it does not.
    pub help: &'static str,
    pub default_value: &'static str,
    pub sensitivity: Sensitivity,
}

impl Setting {
    /// Every setting, in the Java enum's order.
    pub const ALL: [Setting; 54] = [
        Setting::EnrichmentEnabled,
        Setting::EolEnabled,
        Setting::EolWarnDays,
        Setting::SastEnabled,
        Setting::ScanDefaultIntervalDays,
        Setting::RetentionKeepPerTarget,
        Setting::RetentionMaxAgeDays,
        Setting::EvidenceRetentionDays,
        Setting::WebhookUrl,
        Setting::TeamsEnabled,
        Setting::TeamsWebhookUrl,
        Setting::SlackWebhookUrl,
        Setting::DiscordWebhookUrl,
        Setting::WebhookSigningSecret,
        Setting::MailRecipients,
        Setting::DigestEnabled,
        Setting::ChecklistRemindersEnabled,
        Setting::NotificationMinSeverity,
        Setting::NotifyOnKev,
        Setting::NotificationAllowPrivateUrl,
        Setting::SiemAllowPrivateDestination,
        Setting::LicenseBlocklist,
        Setting::TargetVisibility,
        Setting::TicketProvider,
        Setting::TicketBaseUrl,
        Setting::TicketProject,
        Setting::TicketToken,
        Setting::TicketWebhookSecret,
        Setting::TicketTokenExpiresOn,
        Setting::TicketUser,
        Setting::TicketIssueType,
        Setting::TicketLabels,
        Setting::TicketAllowPrivateUrl,
        Setting::TicketCa,
        Setting::AiReviewEnabled,
        Setting::AiReviewOwaspAfterScan,
        Setting::AiReviewProvider,
        Setting::AiReviewOllamaUrl,
        Setting::AiReviewOpenaiUrl,
        Setting::AiReviewOpenaiKey,
        Setting::AiReviewModel,
        Setting::AiReviewTimeoutSeconds,
        Setting::AiReviewAllowRemote,
        Setting::AiReviewRiskAcknowledgedBy,
        Setting::AiReviewRiskAcknowledgedAt,
        Setting::ComplianceFreshnessDays,
        Setting::IsmsScopeStatement,
        Setting::IsmsScopeAssets,
        Setting::SlaCriticalDays,
        Setting::SlaHighDays,
        Setting::SlaMediumDays,
        Setting::SlaLowDays,
        Setting::FourEyesApprovalRequired,
        Setting::ChecklistAutoAnswer,
    ];

    /// The Java constant's name.
    pub const fn name(self) -> &'static str {
        match self {
            Setting::EnrichmentEnabled => "ENRICHMENT_ENABLED",
            Setting::EolEnabled => "EOL_ENABLED",
            Setting::EolWarnDays => "EOL_WARN_DAYS",
            Setting::SastEnabled => "SAST_ENABLED",
            Setting::ScanDefaultIntervalDays => "SCAN_DEFAULT_INTERVAL_DAYS",
            Setting::RetentionKeepPerTarget => "RETENTION_KEEP_PER_TARGET",
            Setting::RetentionMaxAgeDays => "RETENTION_MAX_AGE_DAYS",
            Setting::EvidenceRetentionDays => "EVIDENCE_RETENTION_DAYS",
            Setting::WebhookUrl => "WEBHOOK_URL",
            Setting::TeamsEnabled => "TEAMS_ENABLED",
            Setting::TeamsWebhookUrl => "TEAMS_WEBHOOK_URL",
            Setting::SlackWebhookUrl => "SLACK_WEBHOOK_URL",
            Setting::DiscordWebhookUrl => "DISCORD_WEBHOOK_URL",
            Setting::WebhookSigningSecret => "WEBHOOK_SIGNING_SECRET",
            Setting::MailRecipients => "MAIL_RECIPIENTS",
            Setting::DigestEnabled => "DIGEST_ENABLED",
            Setting::ChecklistRemindersEnabled => "CHECKLIST_REMINDERS_ENABLED",
            Setting::NotificationMinSeverity => "NOTIFICATION_MIN_SEVERITY",
            Setting::NotifyOnKev => "NOTIFY_ON_KEV",
            Setting::NotificationAllowPrivateUrl => "NOTIFICATION_ALLOW_PRIVATE_URL",
            Setting::SiemAllowPrivateDestination => "SIEM_ALLOW_PRIVATE_DESTINATION",
            Setting::LicenseBlocklist => "LICENSE_BLOCKLIST",
            Setting::TargetVisibility => "TARGET_VISIBILITY",
            Setting::TicketProvider => "TICKET_PROVIDER",
            Setting::TicketBaseUrl => "TICKET_BASE_URL",
            Setting::TicketProject => "TICKET_PROJECT",
            Setting::TicketToken => "TICKET_TOKEN",
            Setting::TicketWebhookSecret => "TICKET_WEBHOOK_SECRET",
            Setting::TicketTokenExpiresOn => "TICKET_TOKEN_EXPIRES_ON",
            Setting::TicketUser => "TICKET_USER",
            Setting::TicketIssueType => "TICKET_ISSUE_TYPE",
            Setting::TicketLabels => "TICKET_LABELS",
            Setting::TicketAllowPrivateUrl => "TICKET_ALLOW_PRIVATE_URL",
            Setting::TicketCa => "TICKET_CA",
            Setting::AiReviewEnabled => "AI_REVIEW_ENABLED",
            Setting::AiReviewOwaspAfterScan => "AI_REVIEW_OWASP_AFTER_SCAN",
            Setting::AiReviewProvider => "AI_REVIEW_PROVIDER",
            Setting::AiReviewOllamaUrl => "AI_REVIEW_OLLAMA_URL",
            Setting::AiReviewOpenaiUrl => "AI_REVIEW_OPENAI_URL",
            Setting::AiReviewOpenaiKey => "AI_REVIEW_OPENAI_KEY",
            Setting::AiReviewModel => "AI_REVIEW_MODEL",
            Setting::AiReviewTimeoutSeconds => "AI_REVIEW_TIMEOUT_SECONDS",
            Setting::AiReviewAllowRemote => "AI_REVIEW_ALLOW_REMOTE",
            Setting::AiReviewRiskAcknowledgedBy => "AI_REVIEW_RISK_ACKNOWLEDGED_BY",
            Setting::AiReviewRiskAcknowledgedAt => "AI_REVIEW_RISK_ACKNOWLEDGED_AT",
            Setting::ComplianceFreshnessDays => "COMPLIANCE_FRESHNESS_DAYS",
            Setting::IsmsScopeStatement => "ISMS_SCOPE_STATEMENT",
            Setting::IsmsScopeAssets => "ISMS_SCOPE_ASSETS",
            Setting::SlaCriticalDays => "SLA_CRITICAL_DAYS",
            Setting::SlaHighDays => "SLA_HIGH_DAYS",
            Setting::SlaMediumDays => "SLA_MEDIUM_DAYS",
            Setting::SlaLowDays => "SLA_LOW_DAYS",
            Setting::FourEyesApprovalRequired => "FOUR_EYES_APPROVAL_REQUIRED",
            Setting::ChecklistAutoAnswer => "CHECKLIST_AUTO_ANSWER",
        }
    }

    /// The setting's definition.
    pub const fn definition(self) -> Definition {
        match self {
            Setting::EnrichmentEnabled => Definition {
                key: "enrichment_enabled",
                setting_type: SettingType::Boolean,
                section: Section::Enrichment,
                label: r#"Apply the EPSS scores and the KEV catalog"#,
                help: r#"Scans read the copies the control plane synchronises; nothing about a scan leaves the machine. Switched off, the "actively exploited" counter stays at zero, which then means "we did not ask" and not "there are none"."#,
                default_value: r#"true"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::EolEnabled => Definition {
                key: "eol_detection_enabled",
                setting_type: SettingType::Boolean,
                section: Section::EndOfLife,
                label: r#"Detect platforms past their support window"#,
                help: r#"A class of risk with no CVE attached: an expired environment will receive no fix for the next vulnerability, whatever it turns out to be. Switching this off leaves existing findings open rather than resolving them — "we stopped looking" is not "it is fixed"."#,
                default_value: r#"true"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::EolWarnDays => Definition {
                key: "eol_warn_days",
                setting_type: SettingType::Integer,
                section: Section::EndOfLife,
                label: r#"Warning window (days)"#,
                help: r#"A cycle whose end falls inside this window is reported at medium severity. Beyond it, nothing: everything reaches end of life one day, and flagging a version supported for another three years would teach people to filter this type out."#,
                default_value: r#"180"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::SastEnabled => Definition {
                key: "sast_enabled",
                setting_type: SettingType::Boolean,
                section: Section::SourceCode,
                label: r#"Analyze the code with Semgrep"#,
                help: r#"Off by default, and that is an operational decision: the first scan of an ordinary repository takes its backlog from a few dozen vulnerabilities to a few thousand findings. Quality findings never fail a build and never trigger a notification. Switching this off leaves existing findings open rather than resolving them."#,
                default_value: r#"false"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::ScanDefaultIntervalDays => Definition {
                key: "scan_default_interval_days",
                setting_type: SettingType::Integer,
                section: Section::Scheduling,
                label: r#"Default rescan interval (days)"#,
                help: r#"How often a repository or an image is rescanned when it has neither an interval nor a cron expression of its own — which is every target added without touching the schedule. A target's own interval or expression always wins, and a target set to "manual only" is never rescanned. Each target has its own moment in the interval, so an estate is spread over the week rather than scanned all at once. Zero means no default: a target with no schedule of its own is then not rescanned, as before 0.11.0."#,
                default_value: r#"7"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::RetentionKeepPerTarget => Definition {
                key: "retention_keep_per_target",
                setting_type: SettingType::Integer,
                section: Section::Retention,
                label: r#"Raw payloads kept per target"#,
                help: r#"The SBOMs and scanner output of each target's last N scans are kept whatever their age. Zero means "no limit on this axis". Findings, issues and summaries are never purged."#,
                default_value: r#"10"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::RetentionMaxAgeDays => Definition {
                key: "retention_max_age_days",
                setting_type: SettingType::Integer,
                section: Section::Retention,
                label: r#"Maximum age of raw payloads (days)"#,
                help: r#"The two rules combine: a payload is purged only if it is both outside the window above and older than this age. Both at zero disables purging."#,
                default_value: r#"90"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::EvidenceRetentionDays => Definition {
                key: "evidence_retention_days",
                setting_type: SettingType::Integer,
                section: Section::Retention,
                label: r#"Evidence kept for (days)"#,
                help: r#"Gate verdicts — every pass and every refusal the barrier returned — the monthly compliance captures and the weekly OWASP record. This is the only record that a control executed, and unlike a payload it cannot be regenerated. A week of the OWASP record is kept while any of it is inside the window. Set it to the period an assessor asks you to cover, plus the delay before they read it; the default is twelve months and five weeks. Zero keeps them for ever. Kept deliberately apart from the payload window above: bounding disk growth and surviving an audit are different questions. Set by a platform governor only: the roles whose controls this record proves do not decide how long it survives."#,
                default_value: r#"400"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::WebhookUrl => Definition {
                key: "notification_webhook_url",
                setting_type: SettingType::Text,
                section: Section::Notifications,
                label: r#"Webhook URL"#,
                help: r#"A generic JSON POST, which reaches Slack, Teams, Discord, Mattermost or a script. Empty disables notifications. The URL is validated on every send: a private destination is refused unless explicitly allowed."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Secret,
            },
            Setting::TeamsEnabled => Definition {
                key: "notification_teams_enabled",
                setting_type: SettingType::Boolean,
                section: Section::Notifications,
                label: r#"Enable Microsoft Teams notifications"#,
                help: r#"Master toggle to enable or disable Microsoft Teams webhook notifications across the application."#,
                default_value: r#"true"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::TeamsWebhookUrl => Definition {
                key: "notification_teams_url",
                setting_type: SettingType::Text,
                section: Section::Notifications,
                label: r#"Microsoft Teams webhook URL"#,
                help: r#"The URL of a Teams workflow — "when a Teams webhook request is received" in Power Automate. The old Office 365 connector was retired, and a workflow is what replaces it. Vectispire posts an Adaptive Card, so nothing has to be mapped in the designer. Empty disables it; it can run beside the generic webhook and the e-mail rather than instead of them."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Secret,
            },
            Setting::SlackWebhookUrl => Definition {
                key: "notification_slack_url",
                setting_type: SettingType::Text,
                section: Section::Notifications,
                label: r#"Slack webhook URL"#,
                help: r#"Incoming webhook URL for posting interactive Slack Block Kit cards. Empty disables it."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Secret,
            },
            Setting::DiscordWebhookUrl => Definition {
                key: "notification_discord_url",
                setting_type: SettingType::Text,
                section: Section::Notifications,
                label: r#"Discord webhook URL"#,
                help: r#"Webhook URL for posting Discord Rich Embed cards. Empty disables it."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Secret,
            },
            Setting::WebhookSigningSecret => Definition {
                key: "notification_webhook_secret",
                setting_type: SettingType::Text,
                section: Section::Notifications,
                label: r#"Webhook signing secret"#,
                help: r#"Signs every webhook message — the global one and each team's — so a receiver can tell a message Vectispire sent from one sent by whoever learned the URL. An `X-Vectispire-Signature` header carries HMAC-SHA256 over the timestamp and the exact body. Worth it for a script, a bus or your own gateway, which can check it; Slack, Teams and Discord accept whatever arrives and will ignore it. Empty means unsigned, which is what every existing deployment stays. Stored encrypted, like a tracker token, and never returned by any route — only by `PUT /api/v1/settings/webhook-secret`."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Encrypted,
            },
            Setting::MailRecipients => Definition {
                key: "notification_mail_to",
                setting_type: SettingType::Text,
                section: Section::Notifications,
                label: r#"E-mail recipients"#,
                help: r#"Comma-separated. Empty disables e-mail. The server itself is configured with `VECTISPIRE_MAIL_HOST` and its companions: a mail relay is deployment infrastructure, not something to retype on a settings screen, and its password has no business in a table this application can export."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::DigestEnabled => Definition {
                key: "notification_digest_enabled",
                setting_type: SettingType::Boolean,
                section: Section::Notifications,
                label: r#"Send a weekly posture report"#,
                help: r#"Every other notification fires when something appears, which is right for an alert and wrong for a report: on a quiet week nobody is told anything — and a quiet week is also the week a target has silently not been scanned for twenty days. This says how much there is, which way it is moving, and what was never examined, once a week, to the global webhook and the e-mail recipients. Off by default: switching it on for an existing deployment would be a silent change to what its channels receive."#,
                default_value: r#"false"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::ChecklistRemindersEnabled => Definition {
                key: "checklist_reminders_enabled",
                setting_type: SettingType::Boolean,
                section: Section::Notifications,
                label: r#"Remind checklist contacts weekly"#,
                help: r#"Once a week, every account a project linked to a profile of its checklist's contact column (PO, BA, Arch…) receives by e-mail the lines of that profile still unanswered, or waiting for confirmation, in the project's draft. A profile with such lines and nobody to remind — no account linked, or one deactivated, without an address or no longer able to fill the checklist in — is listed to the CISOs instead. Needs the mail relay (`VECTISPIRE_MAIL_HOST`); the recipients are the accounts' own addresses, not the e-mail recipients above. Off by default."#,
                default_value: r#"false"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::NotificationMinSeverity => Definition {
                key: "notification_min_severity",
                setting_type: SettingType::Severity,
                section: Section::Notifications,
                label: r#"Minimum severity notified"#,
                help: r#"Nothing new above this threshold, no message. One notification per scan teaches people to filter the channel."#,
                default_value: r#"high"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::NotifyOnKev => Definition {
                key: "notification_always_on_kev",
                setting_type: SettingType::Boolean,
                section: Section::Notifications,
                label: r#"Notify any actively exploited vulnerability"#,
                help: r#"Whatever its severity: the threshold alone would discard a "medium" being exploited today."#,
                default_value: r#"true"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::NotificationAllowPrivateUrl => Definition {
                key: "notification_allow_private_url",
                setting_type: SettingType::Boolean,
                section: Section::Notifications,
                label: r#"Allow a private webhook URL"#,
                help: r#"For an internal bus. Off by default, and set by an administrator only: a webhook URL resolving to a private address is far more often a server-side request forgery attempt than an intranet endpoint, and the channels are configured and tested by a security lead. The instance metadata endpoint stays refused in every case."#,
                default_value: r#"false"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::SiemAllowPrivateDestination => Definition {
                key: "siem_allow_private_destination",
                setting_type: SettingType::Boolean,
                section: Section::Notifications,
                label: r#"Allow a private SIEM destination"#,
                help: r#"For a collector on the internal network. Off by default, and set by an administrator only: the SIEM export is configured by a security lead, and a private destination opens the internal network to it. Vectispire's own database and Docker daemon and the instance metadata endpoint stay refused in every case."#,
                default_value: r#"false"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::LicenseBlocklist => Definition {
                key: "license_blocklist",
                setting_type: SettingType::Text,
                section: Section::Licenses,
                label: r#"Forbidden licenses"#,
                help: r#"Comma-separated SPDX identifiers, for example "GPL-3.0-only,AGPL-3.0-only". Empty, nothing is reported: which licenses are forbidden is an organizational decision, not a technical one. Read from the SBOM already produced — no extra tool is needed."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::TargetVisibility => Definition {
                key: "target_visibility",
                setting_type: SettingType::Text,
                section: Section::Access,
                label: r#"What a non-administrator sees"#,
                help: r#""everyone" means every signed-in account sees every target — the behaviour of a deployment that has never thought about it, and the value an upgrade keeps so that nothing blanks overnight. "assigned" means an account sees only the targets an administrator has assigned to it, and an account with no assignment sees nothing. Administrators always see everything: somebody has to be able to make the assignments. A new installation is created with "assigned" — the safe value is written into the table when the database is empty, which is the one moment it cannot break anything."#,
                default_value: r#"everyone"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::TicketProvider => Definition {
                key: "ticket_provider",
                setting_type: SettingType::Text,
                section: Section::Tickets,
                label: r#"Provider"#,
                help: r#""gitlab", "github", "jira", "servicenow", or "none" to disable. A ticket is opened for any issue that would fail a build under the gate policy — there is no second threshold, so that one single place defines "serious enough to act on"."#,
                default_value: r#"none"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::TicketBaseUrl => Definition {
                key: "ticket_base_url",
                setting_type: SettingType::Text,
                section: Section::Tickets,
                label: r#"Tracker URL"#,
                help: r#"An internal destination is accepted here, unlike the webhook: a self-hosted GitLab or Jira commonly lives on an internal network. The instance metadata endpoint stays refused."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Secret,
            },
            Setting::TicketProject => Definition {
                key: "ticket_project",
                setting_type: SettingType::Text,
                section: Section::Tickets,
                label: r#"Project"#,
                help: r#"The GitLab path ("group/project"), the GitHub repository ("owner/repository") or the Jira project key ("SEC"). Set by an administrator only: the tracker token goes wherever this points, on the tracker's host."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::TicketToken => Definition {
                key: "ticket_token",
                setting_type: SettingType::Text,
                section: Section::Tickets,
                label: r#"Access token"#,
                help: r#"Grants write access to the tracker, which is a different class of secret from a webhook URL: it is therefore encrypted at rest like an SSH key, not stored in the clear alongside the other settings. Written only by `PUT /api/v1/settings/ticket-token`."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Encrypted,
            },
            Setting::TicketWebhookSecret => Definition {
                key: "ticket_webhook_secret",
                setting_type: SettingType::Text,
                section: Section::Tickets,
                label: r#"Inbound webhook secret"#,
                help: r#"Authenticates the tracker calling us, which is the opposite direction from the access token above. The webhook route is anonymous by necessity — Jira holds no session — and it moves a triage decision, so without this an anonymous caller who guesses a ticket reference can close a finding. GitLab sends `X-Gitlab-Token` verbatim; GitHub sends `X-Hub-Signature-256` as HMAC-SHA256 over the raw body; Jira and ServiceNow have no convention, so a shared token in `X-Vectispire-Token` is accepted for those. While it is empty the route refuses every call with a 403 telling the tracker the webhook is not configured: set it, then set the same value in the tracker. Encrypted at rest and written only by `PUT /api/v1/settings/ticket-webhook-secret`."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Encrypted,
            },
            Setting::TicketTokenExpiresOn => Definition {
                key: "ticket_token_expires_on",
                setting_type: SettingType::Text,
                section: Section::Tickets,
                label: r#"Token expiry date"#,
                help: r#"The date the access token stops working, as YYYY-MM-DD, for a tracker that does not report it — Jira and ServiceNow. GitLab and GitHub report their tokens' expiry, read when the token is saved and daily after; this date applies to them only when they report none. The settings screen announces it fourteen days ahead; empty, the expiry is shown as unknown. Set by an administrator only, like the token it describes."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::TicketUser => Definition {
                key: "ticket_user",
                setting_type: SettingType::Text,
                section: Section::Tickets,
                label: r#"Jira account"#,
                help: r#"The account address, required by Jira alongside the token for basic authentication. ServiceNow uses it the same way when it is set, and the token alone otherwise; GitLab and GitHub do not use it. Set by an administrator only, like the token it travels with."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::TicketIssueType => Definition {
                key: "ticket_issue_type",
                setting_type: SettingType::Text,
                section: Section::Tickets,
                label: r#"Jira issue type"#,
                help: r#"The type name in the target Jira project. The other trackers do not use it."#,
                default_value: r#"Bug"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::TicketLabels => Definition {
                key: "ticket_labels",
                setting_type: SettingType::Text,
                section: Section::Tickets,
                label: r#"Labels"#,
                help: r#"Comma-separated, applied to every ticket opened on GitLab, GitHub or Jira. ServiceNow incidents carry no labels."#,
                default_value: r#"vectispire,security"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::TicketAllowPrivateUrl => Definition {
                key: "ticket_allow_private_url",
                setting_type: SettingType::Boolean,
                section: Section::Tickets,
                label: r#"Allow an internal URL"#,
                help: r#"On by default. Clear it for a deployment that only uses a hosted tracker."#,
                default_value: r#"true"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::TicketCa => Definition {
                key: "ticket_ca_pem",
                setting_type: SettingType::Text,
                section: Section::Tickets,
                label: r#"Tracker CA (PEM)"#,
                help: r#"For a tracker whose certificate comes from your organisation's own CA: paste that CA's certificate in PEM form (-----BEGIN CERTIFICATE-----), a root and its intermediates if need be. Used for the tracker only, and in place of the server's trust store — the public CAs are then not trusted for it; the tracker's name is still verified. Empty, the server's trust store applies. Set by an administrator only: it decides whom the tracker token is presented to."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Secret,
            },
            Setting::AiReviewEnabled => Definition {
                key: "ai_review_enabled",
                setting_type: SettingType::Boolean,
                section: Section::ModelReview,
                label: r#"Let a model write the OWASP report"#,
                help: r#"Today this switch turns on one thing: the OWASP report written by the model configured below, asked from the OWASP page or, with the next setting, after each repository scan. The model is sent the repository's open findings — identifiers, components, paths, descriptions — not its source, though a description can quote a line of it. The report is a document: nothing in it becomes an issue, and nothing in it reaches a gate. No scan reviews the code with a model: that review is not wired, and a scan examines exactly the same with this on as with it off."#,
                default_value: r#"false"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::AiReviewOwaspAfterScan => Definition {
                key: "ai_review_owasp_after_scan",
                setting_type: SettingType::Boolean,
                section: Section::ModelReview,
                label: r#"Write the OWASP report after each repository scan"#,
                help: r#"When a repository's scan completes, Vectispire asks the model for that repository's OWASP report, as the button on its page does — what is sent is the same: the open findings, never the source. Only while model review is on; never for a failed scan or a container image. One report at a time, beside the scans and never holding them up: a repository whose report is still being written is not asked again, and scans arriving while one waits are folded into it. A failure is recorded on the report, as for a report asked by hand, and the scan stays completed."#,
                default_value: r#"false"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::AiReviewProvider => Definition {
                key: "ai_review_provider",
                setting_type: SettingType::Text,
                section: Section::ModelReview,
                label: r#"Provider"#,
                help: r#"`ollama` keeps what is sent on a machine you run. `openai` sends it to OpenAI. That is the whole difference, and it is not a performance one: with `openai`, the open findings of every repository whose report is written — identifiers, components, file paths and descriptions, of private repositories too, a description able to quote a committed line — leave your estate in the body of an HTTPS request to a third party, who applies their own retention and their own jurisdiction to it; the day the code review is wired, the source of every scanned repository will, and whatever secrets are still committed in it. Check what your contract with them says about training and retention before turning this on, and check whether what you scan is yours to send. Requires an API key, and the acknowledgement below."#,
                default_value: r#"ollama"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::AiReviewOllamaUrl => Definition {
                key: "ai_review_ollama_url",
                setting_type: SettingType::Text,
                section: Section::ModelReview,
                label: r#"Ollama service URL"#,
                help: r#"This endpoint receives the open findings of every repository whose report is written — identifiers, components, paths, descriptions — and will receive its source code the day the code review is wired. The risk is therefore not that it points inward, but outward: a well-formed public URL is exactly what an exfiltration channel looks like. A public destination is refused unless explicitly acknowledged below."#,
                default_value: r#"http://localhost:11434"#,
                sensitivity: Sensitivity::Secret,
            },
            Setting::AiReviewOpenaiUrl => Definition {
                key: "ai_review_openai_url",
                setting_type: SettingType::Text,
                section: Section::ModelReview,
                label: r#"OpenAI-compatible API URL"#,
                help: r#"The API root, without `/chat/completions` — it is appended. Public and local are both allowed, and the same rule decides which: this URL goes through the outbound guard exactly like the Ollama one, so a public destination is refused until the acknowledgement below is on. Left at OpenAI's own address, what is sent goes to OpenAI. Pointed at vLLM, LM Studio, llama.cpp or an internal gateway — anything speaking the same wire protocol — it never leaves, and no acknowledgement is needed."#,
                default_value: r#"https://api.openai.com/v1"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::AiReviewOpenaiKey => Definition {
                key: "ai_review_openai_key",
                setting_type: SettingType::Text,
                section: Section::ModelReview,
                label: r#"OpenAI API key"#,
                help: r#"Sent as `Authorization: Bearer`. Stored encrypted, like a tracker token, and never returned by any route — a screen shows whether one is configured, never the key. A local endpoint that authenticates nobody can be left without one."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Encrypted,
            },
            Setting::AiReviewModel => Definition {
                key: "ai_review_model",
                setting_type: SettingType::Text,
                section: Section::ModelReview,
                label: r#"Model"#,
                help: r#"The name as the provider knows it — an Ollama tag, or a model your OpenAI account may call. It does not have to exist yet to be saved here; the connection test is what says whether it does."#,
                default_value: r#"gemma4:12b-it-qat"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::AiReviewTimeoutSeconds => Definition {
                key: "ai_review_timeout_seconds",
                setting_type: SettingType::Integer,
                section: Section::ModelReview,
                label: r#"How long to wait for the model (seconds)"#,
                help: r#"A local model writing a report takes minutes on ordinary hardware, and the ten seconds that suit a webhook turn every run into "request timed out" — which reads as a broken Ollama rather than as a limit set here. The right value depends on the machine and the model, which is why it is a setting and not a constant."#,
                default_value: r#"300"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::AiReviewAllowRemote => Definition {
                key: "ai_review_allow_remote_url",
                setting_type: SettingType::Boolean,
                section: Section::ModelReview,
                label: r#"Allow a public model endpoint"#,
                help: r#"Off by default, and it is the most consequential setting on this screen: turning it on allows the findings of every scanned repository — and, once the code review is wired, its source code — to be sent to a host outside your estate — OpenAI's API, or any other public address entered above. Leave it off and both providers are held to a destination on your own network. It governs the URL, not the provider: a local OpenAI-compatible endpoint needs nothing acknowledged."#,
                default_value: r#"false"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::AiReviewRiskAcknowledgedBy => Definition {
                key: "ai_review_risk_acknowledged_by",
                setting_type: SettingType::Text,
                section: Section::ModelReview,
                label: r#"Data-leak risk accepted by"#,
                help: r#"The account that turned on the public endpoint, recorded by the server at that moment. Empty means nobody has — which is also what it says after somebody turned it back off."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::AiReviewRiskAcknowledgedAt => Definition {
                key: "ai_review_risk_acknowledged_at",
                setting_type: SettingType::Text,
                section: Section::ModelReview,
                label: r#"Data-leak risk accepted on"#,
                help: r#"When that acceptance was recorded, in UTC. The audit log holds the same event and is never purged; this row is what the screen can show without a query."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::ComplianceFreshnessDays => Definition {
                key: "compliance_freshness_days",
                setting_type: SettingType::Integer,
                section: Section::Remediation,
                label: r#"Compliance: an observation counts as current for"#,
                help: r#"A target never observed has no known vulnerability, and on a naive dashboard it is green — the one green that should raise an alarm. Past this number of days a scan stops counting as a current observation, and a control assessed on incomplete coverage can no longer be reported compliant: it is "not assessed", which is a different sentence in front of an auditor. Zero disables the ceiling and gives the assessment back its earlier behaviour."#,
                default_value: r#"30"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::IsmsScopeStatement => Definition {
                key: "isms_scope_statement",
                setting_type: SettingType::Text,
                section: Section::Retention,
                label: r#"Certified scope"#,
                help: r#"What the management system's certified scope covers, in the words of the document that defines it. Copied here so an evidence bundle carries the scope it describes — an archive whose reader has to be told separately what it was about is half an archive."#,
                default_value: r#""#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::IsmsScopeAssets => Definition {
                key: "isms_scope_assets",
                setting_type: SettingType::Integer,
                section: Section::Retention,
                label: r#"Assets the certified scope covers"#,
                help: r#"A tool measuring its own coverage always reports full coverage. Vectispire knows the targets somebody registered in it; an asset inside the certified scope that was never registered has no row here to be missing from, so an estate made of half the certified assets reports as entirely scanned. Taken from the scope document, this number is what makes the difference visible. Zero means nobody has said — which is reported as undeclared, never as complete."#,
                default_value: r#"0"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::SlaCriticalDays => Definition {
                key: "sla_critical_days",
                setting_type: SettingType::Integer,
                section: Section::Remediation,
                label: r#"Critical: days to remediate"#,
                help: r#"Counted from when the issue was first seen, never from the last scan — otherwise a target scanned nightly would reset every deadline every night and nothing would ever be late. Zero disables the deadline for this severity. No window blocks a gate: being late is reported to people, not used to stop a deployment that might carry the fix."#,
                default_value: r#"15"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::SlaHighDays => Definition {
                key: "sla_high_days",
                setting_type: SettingType::Integer,
                section: Section::Remediation,
                label: r#"High: days to remediate"#,
                help: r#"As above: from the first sighting, zero to disable, and it blocks nothing."#,
                default_value: r#"30"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::SlaMediumDays => Definition {
                key: "sla_medium_days",
                setting_type: SettingType::Integer,
                section: Section::Remediation,
                label: r#"Medium: days to remediate"#,
                help: r#"As above: from the first sighting, zero to disable, and it blocks nothing."#,
                default_value: r#"90"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::SlaLowDays => Definition {
                key: "sla_low_days",
                setting_type: SettingType::Integer,
                section: Section::Remediation,
                label: r#"Low: days to remediate"#,
                help: r#"As above. Negligible and unknown severities carry no window at all and are not settable: neither describes work anybody schedules, and a deadline on either would fill the report with lateness that means nothing."#,
                default_value: r#"180"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::FourEyesApprovalRequired => Definition {
                key: "triage_four_eyes_required",
                setting_type: SettingType::Boolean,
                section: Section::Triage,
                label: r#"Require double validation (Four-Eyes approval) for VEX triage"#,
                help: r#"When enabled, marking an issue as NOT_AFFECTED, WILL_NOT_FIX or FIXED by a user without CISO/Admin approval privileges creates a PENDING_APPROVAL request. When disabled, any authorized user can directly settle triage decisions."#,
                default_value: r#"true"#,
                sensitivity: Sensitivity::Plain,
            },
            Setting::ChecklistAutoAnswer => Definition {
                key: "checklist_auto_answer",
                setting_type: SettingType::Boolean,
                section: Section::Checklists,
                label: r#"Answer measured checklist lines automatically"#,
                help: r#"When a scan or an import completes, and when a checklist is opened or moved to another version, Vectispire answers every line bound to a rule in a draft checklist: yes when it passes, no with the measurement as its comment when it fails, nothing when there is no data. The answers are marked as Vectispire's, never replace a person's, and a person still submits and signs off. Switched off, existing answers stay and nothing new is written automatically; answering as measured in one click remains."#,
                default_value: r#"true"#,
                sensitivity: Sensitivity::Plain,
            },
        }
    }

    /// The credential this setting decides the destination of, if it decides one — **whoever may point a
    /// credential somewhere must be allowed to hold it**: the tracker's base URL, project, user, CA and the
    /// switch to a private host direct the tracker token; the OpenAI URL and the remote switch, the OpenAI key.
    pub const fn directs_credential(self) -> Option<Setting> {
        match self {
            Setting::TicketBaseUrl
            | Setting::TicketProject
            | Setting::TicketUser
            | Setting::TicketAllowPrivateUrl
            | Setting::TicketCa => Some(Setting::TicketToken),
            Setting::AiReviewOpenaiUrl | Setting::AiReviewAllowRemote => Some(Setting::AiReviewOpenaiKey),
            _ => None,
        }
    }

    /// Whether only the platform governor may change it: every setting of the access, triage and checklist
    /// sections — a rule, not a parameter — and the evidence window, which the roles the evidence judges do
    /// not decide.
    pub const fn governor_only(self) -> bool {
        matches!(self.definition().section, Section::Access | Section::Triage | Section::Checklists)
            || matches!(self, Setting::EvidenceRetentionDays)
    }

    /// Whether changing it changes what the deployment protects, and so is forwarded to the SOC. **No wildcard
    /// arm**: a setting added to the catalog does not compile until whoever adds it has answered.
    pub const fn governs_security(self) -> bool {
        match self {
            Setting::EvidenceRetentionDays
            | Setting::WebhookSigningSecret
            | Setting::NotificationAllowPrivateUrl
            | Setting::SiemAllowPrivateDestination
            | Setting::TargetVisibility
            | Setting::TicketBaseUrl
            | Setting::TicketProject
            | Setting::TicketToken
            | Setting::TicketWebhookSecret
            | Setting::TicketUser
            | Setting::TicketAllowPrivateUrl
            | Setting::TicketCa
            | Setting::AiReviewOllamaUrl
            | Setting::AiReviewOpenaiUrl
            | Setting::AiReviewOpenaiKey
            | Setting::AiReviewAllowRemote
            | Setting::FourEyesApprovalRequired
            | Setting::ChecklistAutoAnswer => true,
            Setting::EnrichmentEnabled
            | Setting::EolEnabled
            | Setting::EolWarnDays
            | Setting::SastEnabled
            | Setting::ScanDefaultIntervalDays
            | Setting::RetentionKeepPerTarget
            | Setting::RetentionMaxAgeDays
            | Setting::WebhookUrl
            | Setting::TeamsEnabled
            | Setting::TeamsWebhookUrl
            | Setting::SlackWebhookUrl
            | Setting::DiscordWebhookUrl
            | Setting::MailRecipients
            | Setting::DigestEnabled
            | Setting::ChecklistRemindersEnabled
            | Setting::NotificationMinSeverity
            | Setting::NotifyOnKev
            | Setting::LicenseBlocklist
            | Setting::TicketProvider
            | Setting::TicketTokenExpiresOn
            | Setting::TicketIssueType
            | Setting::TicketLabels
            | Setting::AiReviewEnabled
            | Setting::AiReviewOwaspAfterScan
            | Setting::AiReviewProvider
            | Setting::AiReviewModel
            | Setting::AiReviewTimeoutSeconds
            | Setting::AiReviewRiskAcknowledgedBy
            | Setting::AiReviewRiskAcknowledgedAt
            | Setting::ComplianceFreshnessDays
            | Setting::IsmsScopeStatement
            | Setting::IsmsScopeAssets
            | Setting::SlaCriticalDays
            | Setting::SlaHighDays
            | Setting::SlaMediumDays
            | Setting::SlaLowDays => false,
        }
    }
}

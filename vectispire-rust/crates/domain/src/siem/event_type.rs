//! `SecurityEventType`: the security events Vectispire forwards to a SOC, and the catalogue a correlation rule
//! is written against.
//!
//! **The signature identifier is a data contract.** A SOC writes its rules on the CEF `Signature ID`, not on the
//! name and not on the variant: changing an identifier silently disarms every rule written against it, in
//! somebody else's SIEM, with nothing on this side to notice. `VECTI-SEC-001` and `VECTI-SEC-004` were declared
//! once and never emitted, and stay out of circulation (decision 0025). **Only what is emitted is listed**: a
//! declared alarm that cannot fire reads as coverage.
//!
//! The wire name — what `Signal` carries, what the outbox stores — is the Java constant's name, so a message
//! queued by either control plane is read by the other.

use crate::severity::Severity;

/// The CEF `outcome` an event of this type carries: a property of the type, not of each call site, so that a
/// SOC never sees `failure`, `failed` and `FAIL` for the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    Success,
    Failure,
    Detected,
}

impl Outcome {
    pub fn wire_name(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Detected => "detected",
        }
    }
}

macro_rules! catalogue {
    ($( $(#[$doc:meta])* $variant:ident = $name:literal, $id:literal, $description:literal, $severity:literal,
        $outcome:ident $(, $follows:literal)?; )*) => {
        /// A security event, in the Java enum's declaration order — the order of [`SecurityEventType::ALL`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum SecurityEventType {
            $( $(#[$doc])* $variant, )*
        }

        impl SecurityEventType {
            /// Every type, in declaration order.
            pub const ALL: &'static [SecurityEventType] = &[ $( SecurityEventType::$variant, )* ];

            /// The Java constant's name: what `Signal` carries and what a queued message stores.
            pub const fn wire_name(self) -> &'static str {
                match self { $( SecurityEventType::$variant => $name, )* }
            }

            /// The CEF `Signature ID` — the contract a SOC's rules are written against.
            pub const fn signature_id(self) -> &'static str {
                match self { $( SecurityEventType::$variant => $id, )* }
            }

            /// The CEF `Name`.
            pub const fn description(self) -> &'static str {
                match self { $( SecurityEventType::$variant => $description, )* }
            }

            /// The type's own severity: every event's, unless the type [follows the
            /// issue](SecurityEventType::follows_issue_severity).
            pub const fn cef_severity(self) -> u8 {
                match self { $( SecurityEventType::$variant => $severity, )* }
            }

            pub const fn outcome(self) -> Outcome {
                match self { $( SecurityEventType::$variant => Outcome::$outcome, )* }
            }

            /// Whether an event of this type takes its CEF severity from the issue it reports on
            /// ([`SecurityEventType::cef_severity_of`]) rather than from the type. Only such a type accepts an
            /// issue's severity: the others keep the one a SOC's rules were written against.
            pub const fn follows_issue_severity(self) -> bool {
                match self { $( SecurityEventType::$variant => catalogue!(@follows $($follows)?), )* }
            }
        }
    };
    (@follows) => { false };
    (@follows $follows:literal) => { $follows };
}

catalogue! {
    /// A finding under watch was newly listed by CISA as exploited in the wild.
    CriticalKevDetected = "CRITICAL_KEV_DETECTED", "VECTI-SEC-002", "Actively exploited vulnerability (KEV) detected",
        10, Detected;
    /// A CI pipeline asked the gate and was refused: a build was blocked by policy.
    SecurityGateFailed = "SECURITY_GATE_FAILED", "VECTI-SEC-003", "Security gate refused a build", 7, Failure;
    /// A triage decision took a finding out of the way without going through an approval — the decision that
    /// makes a dashboard look better is the one a SOC wants to be able to question.
    TriageSettled = "TRIAGE_SETTLED", "VECTI-SEC-005", "Finding settled by triage", 5, Success;
    /// An emergency MFA recovery code was consumed: either a lost phone or a stolen code sheet.
    MfaBackupCodeUsed = "MFA_BACKUP_CODE_USED", "VECTI-SEC-006", "MFA backup code consumed", 6, Success;
    /// The password sign-in throttle refused an attempt.
    SignInThrottled = "SIGN_IN_THROTTLED", "VECTI-SEC-007", "Sign-in failure ceiling reached", 7, Failure;
    /// A second-factor challenge was destroyed after too many wrong codes.
    MfaFailureCeiling = "MFA_FAILURE_CEILING", "VECTI-SEC-008", "MFA failure ceiling reached", 7, Failure;
    /// An address presented too many refused bearer tokens and is answered 429 until the window refills.
    BearerTokenThrottled = "BEARER_TOKEN_THROTTLED", "VECTI-SEC-009", "Bearer token failure ceiling reached", 7,
        Failure;
    /// An account was created, deleted, or changed role, activation, password, second factor or visible targets.
    AccountChanged = "ACCOUNT_CHANGED", "VECTI-SEC-010", "Account privileges or credentials changed", 6, Success;
    /// A team's members or targets changed: somebody gained or lost access to part of the estate.
    AccessGrantChanged = "ACCESS_GRANT_CHANGED", "VECTI-SEC-011", "Team access grant changed", 6, Success;
    ApiKeyIssued = "API_KEY_ISSUED", "VECTI-SEC-012", "API key issued", 5, Success;
    ApiKeyRevoked = "API_KEY_REVOKED", "VECTI-SEC-013", "API key revoked", 4, Success;
    /// A remote agent was declared, enabled, disabled, deleted, its signing key pinned or removed, or its sealing
    /// key reset.
    AgentChanged = "AGENT_CHANGED", "VECTI-SEC-014", "Agent declared or its credentials changed", 6, Success;
    AgentResultRefused = "AGENT_RESULT_REFUSED", "VECTI-SEC-015", "Agent result refused: attestation did not verify",
        8, Failure;
    TriageApproved = "TRIAGE_APPROVED", "VECTI-SEC-016", "Four-eyes triage request approved", 5, Success;
    TriageRefused = "TRIAGE_REFUSED", "VECTI-SEC-017", "Four-eyes triage request refused", 4, Failure;
    /// The audit log's hash chain, or its mirror, no longer agrees with itself.
    AuditChainBroken = "AUDIT_CHAIN_BROKEN", "VECTI-SEC-018", "Audit log integrity verification failed", 10, Failure;
    /// A setting that governs security changed: SIEM export, four-eyes, visibility, a gate policy, a credential.
    SecuritySettingChanged = "SECURITY_SETTING_CHANGED", "VECTI-SEC-019", "Security-relevant setting changed", 6,
        Success;
    /// An agent's sealing key was refused: its signature did not verify against the pinned key, or it was older
    /// than the key already accepted. No credential is sealed for it.
    AgentSealingKeyRefused = "AGENT_SEALING_KEY_REFUSED", "VECTI-SEC-020",
        "Agent sealing key refused: signature or generation did not verify", 8, Failure;
    /// Third-party code gained or lost read access to some of the estate's source, or was let run unsigned.
    PluginChanged = "PLUGIN_CHANGED", "VECTI-SEC-021", "Analysis plugin registered, changed or activated", 6, Success;
    SarifSourceChanged = "SARIF_SOURCE_CHANGED", "VECTI-SEC-022", "SARIF import source declared or changed", 6,
        Success;
    /// Either a misconfigured pipeline or a key used for something it was not issued for.
    SarifImportRefused = "SARIF_IMPORT_REFUSED", "VECTI-SEC-023",
        "SARIF import refused: undeclared source, scope or tool", 5, Failure;
    /// What every project's checklist attests to has changed (decision 0032 §9).
    ChecklistTemplateChanged = "CHECKLIST_TEMPLATE_CHANGED", "VECTI-SEC-024",
        "Checklist template version published or retired", 6, Success;
    ChecklistSignedOff = "CHECKLIST_SIGNED_OFF", "VECTI-SEC-025", "Checklist signed off", 5, Success;
    ChecklistSignOffRefused = "CHECKLIST_SIGN_OFF_REFUSED", "VECTI-SEC-026", "Checklist sign-off refused or returned",
        5, Failure;
    /// `VECTI-SEC-023`'s twin for the reports a checklist reads (decision 0032).
    ReportImportRefused = "REPORT_IMPORT_REFUSED", "VECTI-SEC-027",
        "Report import refused: undeclared source, kind or scope", 5, Failure;
    /// Sent synchronously to the collector being left, whatever the severity filter says: queued, it would be
    /// read against the configuration that no longer names this collector, and dropped.
    SiemExportStopped = "SIEM_EXPORT_STOPPED", "VECTI-SEC-028", "SIEM export switched off or redirected", 7, Success;
    /// Once per issue, when it is created: a leak seen again is the same leak.
    SecretLeakDetected = "SECRET_LEAK_DETECTED", "VECTI-SEC-029", "Secret leaked in source code", 8, Detected;
    /// **As severe as the late issue.** At a fixed 6 it sat under the factory minimum (`HIGH`), so out of the box
    /// no breach ever reached the SOC; the 6 stays as the default for an event queued before the upgrade.
    SlaBreached = "SLA_BREACHED", "VECTI-SEC-030", "Remediation deadline passed", 6, Detected, true;
    ReportPluginChanged = "REPORT_PLUGIN_CHANGED", "VECTI-SEC-031",
        "Report plugin registered, changed, approved, activated or withdrawn", 6, Success;
    /// A project's whole triaged state left the platform (decision 0035 §4).
    ProjectExported = "PROJECT_EXPORTED", "VECTI-SEC-032", "Project export left the platform", 4, Success;
    /// How a tampered report plugin shows itself; an ordinary failed run is audited, not signalled.
    ReportPluginRefused = "REPORT_PLUGIN_REFUSED", "VECTI-SEC-033", "Report plugin refused, or its output refused", 6,
        Failure;
    ForgeConnectionChanged = "FORGE_CONNECTION_CHANGED", "VECTI-SEC-034",
        "Forge connection created, its token or trust replaced, or deleted", 6, Success;
    /// Once per import, with its counts, never once per target.
    ForgeImportApplied = "FORGE_IMPORT_APPLIED", "VECTI-SEC-035", "Repositories imported from a forge", 5, Success;
    /// How an SSRF or a credential-harvesting attempt through the connection form shows itself.
    ForgeConnectionRefused = "FORGE_CONNECTION_REFUSED", "VECTI-SEC-036",
        "Forge connection refused: blocked destination, write scope, or a credential presented to another host", 5,
        Failure;
    /// A tracker closed a ticket in words that contradict a settled triage decision (decision 0041).
    TrackerContradictsTriage = "TRACKER_CONTRADICTS_TRIAGE", "VECTI-SEC-037",
        "A tracker contradicts a settled triage decision", 4, Detected;
    /// Below the factory minimum on purpose: a token still working is a task for this fortnight.
    IntegrationTokenExpiring = "INTEGRATION_TOKEN_EXPIRING", "VECTI-SEC-038", "Integration token expires soon", 4,
        Detected;
    /// At the factory minimum, so that it reaches a SOC out of the box.
    IntegrationTokenStopped = "INTEGRATION_TOKEN_STOPPED", "VECTI-SEC-039",
        "Integration token stopped working: expired or refused", 7, Failure;
    IntegrationTokenRestored = "INTEGRATION_TOKEN_RESTORED", "VECTI-SEC-040", "Integration token working again", 2,
        Success;
    /// The connection test. Sent whatever the severity filter says, since it tests the filter's destination.
    PingTest = "PING_TEST", "VECTI-SEC-999", "SIEM connector health check", 1, Success;
}

impl SecurityEventType {
    /// `valueOf`: the type a wire name names, exactly as written, or `None`.
    pub fn from_wire_name(name: &str) -> Option<SecurityEventType> {
        SecurityEventType::ALL.iter().copied().find(|kind| kind.wire_name() == name)
    }

    /// An issue's severity as the CEF severity of an event about it — the one place it is decided.
    ///
    /// Inside the CEF band of the same name and below its top, so that the configured minimum lets an issue's
    /// event through exactly from the issue's own severity. A critical takes 8 and not 9: 9–10 is kept for what
    /// is exploited or broken now (a KEV, the audit chain). A match without a wildcard, so a severity added to
    /// [`Severity`] has to be placed here.
    pub const fn cef_severity_of(issue_severity: Severity) -> u8 {
        match issue_severity {
            Severity::Critical => 8,
            Severity::High => 7,
            Severity::Medium => 5,
            Severity::Low | Severity::Negligible | Severity::Unknown => 3,
        }
    }
}

/// Where an audit operation stands with the SOC, on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// The operation is unambiguous: every entry of it is this event.
    Signals(SecurityEventType),
    /// The operation signals nothing by itself — routine, or too broad, in which case its writer names the
    /// event on the entries that are one (`Record::signalling`).
    Quiet,
}

/// `SecurityEventType.signalledBy`: the event an audit entry signals on its own, by the operation's wire name.
///
/// **Only the unambiguous operations signal.** `LOGIN_BLOCKED` is written by the throttle and also when
/// password sign-in is switched off; `SETTING_UPDATED` covers a repository's branch as well as the four-eyes
/// switch; `ISSUE_TRIAGED` a ticket link as well as a dismissal. Mapping those would flood a SOC or miss what it
/// wants, so their writers name the event themselves and this answers `None`. A name no operation has answers
/// `None` too (Java's `null`).
pub fn signalled_by(operation: &str) -> Option<SecurityEventType> {
    match placement(operation)? {
        Placement::Signals(kind) => Some(kind),
        Placement::Quiet => None,
    }
}

/// Where an operation is placed, or `None` when this catalogue does not know the name.
///
/// The Java switch is exhaustive over `AuditOperation`, so a new operation cannot compile until somebody places
/// it. The operation list lives in `cp-audit`, which this crate cannot see; `cp-audit`'s tests hold every
/// operation to a placement here and every name here to an operation, which is the same guarantee one build
/// later. **Listed rather than defaulted**: a default would decide for whoever adds the operation, silently.
pub fn placement(operation: &str) -> Option<Placement> {
    if let Some((_, kind)) = SIGNALLING.iter().find(|(name, _)| *name == operation) {
        return Some(Placement::Signals(*kind));
    }
    QUIET.contains(&operation).then_some(Placement::Quiet)
}

use SecurityEventType as E;

/// The operations that signal on their own, and what.
pub const SIGNALLING: &[(&str, SecurityEventType)] = &[
    ("USER_CREATED", E::AccountChanged),
    ("USER_UPDATED", E::AccountChanged),
    ("USER_DELETED", E::AccountChanged),
    ("USER_PASSWORD_RESET", E::AccountChanged),
    ("PASSWORD_CHANGED", E::AccountChanged),
    // Filing or moving a repository or an image moves it in or out of every project grant at once (decision
    // 0023): who may see it changes, with no grant row touched.
    ("TEAM_ACCESS_CHANGED", E::AccessGrantChanged),
    ("PROJECT_REPOSITORIES_CHANGED", E::AccessGrantChanged),
    ("PROJECT_CONTAINERS_CHANGED", E::AccessGrantChanged),
    ("API_KEY_CREATED", E::ApiKeyIssued),
    ("API_KEY_DELETED", E::ApiKeyRevoked),
    ("AGENT_CREATED", E::AgentChanged),
    ("AGENT_UPDATED", E::AgentChanged),
    ("AGENT_DELETED", E::AgentChanged),
    ("AGENT_SIGNING_KEY_PINNED", E::AgentChanged),
    ("AGENT_SEALING_KEY_RESET", E::AgentChanged),
    ("AGENT_RESULT_REFUSED", E::AgentResultRefused),
    ("AGENT_SEALING_KEY_REFUSED", E::AgentSealingKeyRefused),
    ("GATE_POLICY_UPDATED", E::SecuritySettingChanged),
    ("PLUGIN_REGISTERED", E::PluginChanged),
    ("PLUGIN_UPDATED", E::PluginChanged),
    ("PLUGIN_ENABLED_CHANGED", E::PluginChanged),
    ("PLUGIN_ACTIVATED", E::PluginChanged),
    ("PLUGIN_DEACTIVATED", E::PluginChanged),
    ("PLUGIN_SIGNATURE_WAIVED", E::PluginChanged),
    ("PLUGIN_SIGNATURE_WAIVER_REVOKED", E::PluginChanged),
    ("SARIF_SOURCE_CHANGED", E::SarifSourceChanged),
    ("SARIF_IMPORT_REFUSED", E::SarifImportRefused),
    ("REPORT_IMPORT_REFUSED", E::ReportImportRefused),
    ("PROJECT_EXPORTED", E::ProjectExported),
    ("REPORT_REFUSED", E::ReportPluginRefused),
    ("FORGE_CONNECTION_REFUSED", E::ForgeConnectionRefused),
    ("TRIAGE_CONTRADICTED_BY_TRACKER", E::TrackerContradictsTriage),
    // One operation per event, and each written once per change of the token's state: unambiguous.
    ("INTEGRATION_TOKEN_EXPIRING", E::IntegrationTokenExpiring),
    ("INTEGRATION_TOKEN_STOPPED", E::IntegrationTokenStopped),
    ("INTEGRATION_TOKEN_RESTORED", E::IntegrationTokenRestored),
    ("REPORT_PLUGIN_REGISTERED", E::ReportPluginChanged),
    ("REPORT_PLUGIN_UPDATED", E::ReportPluginChanged),
    ("REPORT_PLUGIN_APPROVED", E::ReportPluginChanged),
    ("REPORT_PLUGIN_ENABLED_CHANGED", E::ReportPluginChanged),
    ("REPORT_PLUGIN_ACTIVATED", E::ReportPluginChanged),
    ("REPORT_PLUGIN_DEACTIVATED", E::ReportPluginChanged),
    ("REPORT_PLUGIN_WITHDRAWN", E::ReportPluginChanged),
    ("CHECKLIST_TEMPLATE_PUBLISHED", E::ChecklistTemplateChanged),
    ("CHECKLIST_SIGNED_OFF", E::ChecklistSignedOff),
    // Returned is refused by another name: what was submitted for signature did not get it.
    ("CHECKLIST_SIGN_OFF_REFUSED", E::ChecklistSignOffRefused),
    ("CHECKLIST_RETURNED", E::ChecklistSignOffRefused),
];

/// The operations that signal nothing by themselves — routine, or too broad, in which case their writers name
/// the event on the entries that are one (`Record::signalling`).
pub const QUIET: &[&str] = &[
    "LOGIN_SUCCESS",
    "LOGIN_FAILURE",
    "LOGIN_BLOCKED",
    "SETTING_UPDATED",
    "ISSUE_TRIAGED",
    "SCAN_TRIGGERED",
    "AI_REVIEW_REQUESTED",
    "REPORT_EXPORTED",
    "TICKET_CREATED",
    "TICKET_LINKED",
    "TICKET_CLOSED",
    "TICKET_SYNCED",
    "CONTROL_DECLARED",
    "TEAM_UPDATED",
    "ACCESS_DENIED",
    // Compliance's record, like a declaration: who drew the scope, not an access change; and a feed refresh
    // anybody with the lead role may ask for at will.
    "CERTIFIED_SCOPE_CHANGED",
    "THREAT_INTEL_SYNCED",
    "AGENT_CREDENTIAL_SENT",
    "AGENT_RESULT_SUBMITTED",
    "BADGE_PUBLISHED",
    // A clone refused, a workspace not made: the operator's to read on the scan. An unsigned report from an
    // agent whose key is pinned is AGENT_RESULT_REFUSED.
    "AGENT_SCAN_FAILED",
    // Bookkeeping of an upgrade: counters given back, nothing anybody did.
    "SCAN_ATTEMPTS_REPAIRED",
    // Every restart of every agent: the refusal is the event, the rotation is routine.
    "AGENT_SEALING_KEY_ACCEPTED",
    "RULE_SET_UPLOADED",
    "RULE_SET_ACTIVATED",
    "RULE_SET_DEACTIVATED",
    "POSTURE_DIGEST_SENT",
    // A name or a description; a project deleted with grants on it names the event itself, since only its
    // writer knows whether any were revoked.
    "SOLUTION_UPDATED",
    "PROJECT_UPDATED",
    // Routine: a pipeline's upload, as frequent as its builds. A refusal is the event.
    "SARIF_IMPORTED",
    "COVERAGE_IMPORTED",
    "TEST_REPORT_IMPORTED",
    "BUILD_SBOM_IMPORTED",
    // A draft being written changes nothing any project attests to: publishing it does.
    "CHECKLIST_TEMPLATE_IMPORTED",
    "CHECKLIST_TEMPLATE_LAYOUT_CONFIRMED",
    "CHECKLIST_TEMPLATE_ITEMS_PAIRED",
    "CHECKLIST_TEMPLATE_EVIDENCE_SET",
    "CHECKLIST_TEMPLATE_RULES_BOUND",
    "CHECKLIST_TEMPLATE_DERIVED",
    // A published version retired is the event, a draft set aside is not: its writer knows which.
    "CHECKLIST_TEMPLATE_RETIRED",
    // A checklist being filled is work, not a security event (§9): the sign-off is one.
    "CHECKLIST_OPENED",
    "CHECKLIST_MOVED_TO_VERSION",
    "CHECKLIST_ANSWERED",
    "CHECKLIST_EVIDENCE_ADDED",
    "CHECKLIST_EVIDENCE_WITHDRAWN",
    "CHECKLIST_SUBMITTED",
    "CHECKLIST_REOPENED",
    // A download of what was attested, like REPORT_EXPORTED: the sign-off was the event.
    "CHECKLIST_EXPORTED",
    // A renaming is not an event: the writer names VECTI-SEC-034 on the creation, the new token or trust, and
    // the deletion.
    "FORGE_CONNECTION_CHANGED",
    // An import that created nothing is not an event: its writer names VECTI-SEC-035 when it did.
    "FORGE_IMPORT_APPLIED",
    // Work going right or wrong (0035 §4): the export each one handed a plugin is PROJECT_EXPORTED.
    "REPORT_REQUESTED",
    "REPORT_PRODUCED",
    "REPORT_FAILED",
    // A read an administrator asked for: the standing access is the connection, VECTI-SEC-034, and a discovery
    // stopped by a page or an address elsewhere is VECTI-SEC-036.
    "FORGE_DISCOVERY_REQUESTED",
    // A download of what was produced — except by the platform governor, whose download its writer names
    // PROJECT_EXPORTED, since only it knows the downloader's role.
    "REPORT_DOWNLOADED",
    // Who is asked to fill a checklist in, and being asked: work, not a security event (§9).
    "CHECKLIST_CONTACT_CHANGED",
    "CHECKLIST_REMINDER_SENT",
];

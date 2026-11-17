//! The access module's settings, as the binary composes them — `vectispire.sign-in.*`, read by the runtime
//! (`Settings::sign_in`), put in force where Java's beans put them: `SignInLimits` on the sign-in's throttle and on the
//! session cleanup (the known clients' retention), `PasswordDerivationLimits` on the bound every password derivation
//! runs under (`PasswordDerivationBound`).
//!
//! **Read once, here, and handed to each.** The settings were read and none of them reached a service: the shipped
//! ceilings held whatever an operator set, with nothing to say so. `tests/access_composition.rs` holds the composition
//! to the settings on a real database.
//!
//! **No database at start** (decision recorded in `SigningKeys::start_lazily`): installing the bound and building the
//! task touch none.

use std::sync::Arc;

use vectispire_cp_access::credentials::CredentialService;
use vectispire_cp_access::derivations::{self, DerivationGate};
use vectispire_cp_access::login_throttle::SignInLimits;
use vectispire_cp_access::throttle::SharedClock;
use vectispire_cp_db::Db;
use vectispire_cp_maintenance::MaintenanceTask;
use vectispire_cp_runtime::settings::SignIn;

/// What the access module was composed with.
pub struct Access {
    /// The ceilings and the retention every sign-in flow is built with (`SignInFlow::with_limits`) — the routes of
    /// task 1.7 take them from here; no access route is served yet.
    pub limits: SignInLimits,
    /// `SESSION_CLEANUP`, under the deployment's retention of known clients.
    pub session_cleanup: Arc<dyn MaintenanceTask>,
}

impl std::fmt::Debug for Access {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Access").field("limits", &self.limits).finish_non_exhaustive()
    }
}

/// `SignInLimits` from the settings. A value the runtime read as zero is the shipped one, as Java's compact
/// constructor reads it ([`SignInLimits::new`]).
pub fn sign_in_limits(settings: &SignIn) -> SignInLimits {
    let ceiling = |value: u32| usize::try_from(value).unwrap_or(usize::MAX);
    SignInLimits::new(
        ceiling(settings.failures_per_account_from_client),
        ceiling(settings.failures_per_account),
        ceiling(settings.failures_per_client),
        time::Duration::try_from(settings.known_client_retention).unwrap_or(time::Duration::MAX),
    )
}

/// `PasswordDerivationLimits`' gate: zero permits are sized from the machine, a zero wait is the shipped two seconds.
pub fn derivation_gate(settings: &SignIn) -> DerivationGate {
    DerivationGate::new(settings.derivations_concurrent, settings.derivations_queue_wait)
}

/// Puts the settings in force: the derivation bound for the whole process, and the cleanup task under the retention.
pub fn compose(settings: &SignIn, credentials: Arc<CredentialService>, db: Db, clock: SharedClock) -> Access {
    derivations::bound(derivation_gate(settings));
    let limits = sign_in_limits(settings);
    Access {
        limits,
        session_cleanup: vectispire_cp_access::session_cleanup::session_cleanup_task_with_limits(
            credentials,
            db,
            clock,
            limits,
        ),
    }
}

/// The access services' audit port on the audit log: each entry under the operation of the same name, its SIEM event
/// when it names one. Recording never fails the gesture it describes, as Java's `record`.
#[derive(Clone)]
pub struct AccessAudit(pub Arc<vectispire_cp_audit::AuditLog>);

impl std::fmt::Debug for AccessAudit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AccessAudit")
    }
}

impl vectispire_cp_access::accounts::Audit for AccessAudit {
    async fn record(&self, record: vectispire_cp_access::accounts::AuditRecord) {
        let Some(operation) = vectispire_cp_audit::AuditOperation::from_wire(record.operation.name()) else {
            // Both enumerations are Java's `AuditOperation`; one the log does not know is a port defect, logged rather
            // than written under another name.
            tracing::error!(operation = record.operation.name(), "An access audit entry names no known operation");
            return;
        };
        let entry = vectispire_cp_audit::Record {
            operation,
            resource_id: Some(record.resource),
            description: Some(record.description),
            user_id: record.username,
            ip_address: record.ip_address,
            user_agent: record.user_agent,
            signal: record.signal.map(vectispire_cp_audit::Signal),
        };
        self.0.record(entry).await;
    }
}

/// What the access module's administration routes are composed from.
#[allow(missing_debug_implementations)] // a bag of parts
pub struct AdministrationParts {
    pub db: Db,
    pub audit: Arc<vectispire_cp_audit::AuditLog>,
    pub credentials: Arc<CredentialService>,
    pub clock: SharedClock,
    pub guard: vectispire_cp_outbound::OutboundUrlGuard,
    pub visibility: vectispire_cp_access::VisibilityService,
    pub targets: Arc<dyn vectispire_cp_access::GrantableTargets>,
}

/// `UsersController`, `AccountRequestsController`, `TeamsController` and `ApiKeysController`, over the services as
/// Java's beans compose them: accounts under four-eyes read from the settings, their writes closing sessions and
/// revoking keys in the account's transaction, a team's channel judged by the outbound guard.
pub fn administration_routes(parts: AdministrationParts) -> Vec<vectispire_cp_http::routes::RouteEntry> {
    use vectispire_cp_access::accounts::{Accounts, ApproverIndependence};
    let AdministrationParts { db, audit, credentials, clock, guard, visibility, targets } = parts;
    let audit = AccessAudit(audit);
    let settings = Arc::new(vectispire_cp_settings::Settings::new(db.clone()));
    let accounts = Accounts::new(
        vectispire_cp_access::SqlAccountStore::new(db.clone(), vectispire_cp_access::CredentialTables),
        audit.clone(),
        clock.clone(),
    )
    .with_four_eyes(ApproverIndependence::new(db.clone(), settings.clone()));
    let teams = vectispire_cp_access::teams::TeamAdministration::new(vectispire_cp_access::teams::TeamParts {
        db: db.clone(),
        audit: audit.clone(),
        clock: clock.clone(),
        outbound: guard,
        policy: settings,
        targets: targets.clone(),
        integrations: crate::registry::integrations(&db),
    });
    let keys = vectispire_cp_access::api_key_administration::ApiKeyAdministration::new(
        vectispire_cp_access::api_key_administration::ApiKeyParts {
            db: db.clone(),
            credentials: (*credentials).clone(),
            targets: targets.clone(),
            issuer_sees: Arc::new(vectispire_cp_access::IssuerVisibility::new(db.clone(), visibility, targets.clone())),
            audit: audit.clone(),
            clock,
        },
    );
    vectispire_cp_access::administration_routes(vectispire_cp_access::Administration {
        accounts: Arc::new(accounts),
        account_targets: Arc::new(vectispire_cp_access::account_targets::AccountTargets::new(db, audit, targets)),
        teams: Arc::new(teams),
        keys: Arc::new(keys),
    })
}

/// What the access module's sign-in routes are composed from.
#[allow(missing_debug_implementations)] // a bag of parts
pub struct SignInRoutesParts {
    pub db: Db,
    pub audit: Arc<vectispire_cp_audit::AuditLog>,
    pub credentials: Arc<CredentialService>,
    pub clock: SharedClock,
    pub encryption: Arc<vectispire_cp_crypto::Encryption>,
    /// The identity provider's name, when one is named (`vectispire.oidc.issuer`).
    pub provider: Option<String>,
    /// `vectispire.oidc.password-login`.
    pub password_login: bool,
    pub branding: vectispire_cp_access::Branding,
    pub limits: SignInLimits,
}

/// `AuthController`, over `AuthenticationFlowService` as Java's beans compose it: the password sign-in allowed unless
/// a provider is named and `vectispire.oidc.password-login` is off, the provider's name as its label, the sign-in
/// ceilings of `vectispire.sign-in.*`. The single sign-on's own endpoints are task 1.4's, not served yet: the methods
/// screen still says what Java says, a provider being named.
pub fn sign_in_routes(parts: SignInRoutesParts) -> Vec<vectispire_cp_http::routes::RouteEntry> {
    let SignInRoutesParts { db, audit, credentials, clock, encryption, provider, password_login, branding, limits } =
        parts;
    let flow = vectispire_cp_access::sign_in::SignInFlow::new(vectispire_cp_access::sign_in::SignInParts {
        users: vectispire_cp_access::SqlAccountStore::new(db.clone(), vectispire_cp_access::CredentialTables),
        audit: AccessAudit(audit),
        store: vectispire_cp_access::SqlSignInStore::new(db),
        sessions: credentials.clone(),
        seal: encryption,
        clock,
        methods: vectispire_cp_access::sign_in::SignInMethodPolicy::new(provider.is_some(), password_login),
        provider_label: provider,
    })
    .with_limits(limits);
    vectispire_cp_access::auth_routes(Arc::new(flow), credentials, branding)
}

/// `ScimUsersController` and `ScimGroupsController`, over `ScimProvisioningService` as Java's beans compose it: a
/// privileged account linked to the directory's subject only under `vectispire.oidc.link-privileged-accounts`.
pub fn scim_routes(
    db: Db,
    audit: Arc<vectispire_cp_audit::AuditLog>,
    clock: SharedClock,
    link_privileged: bool,
) -> Vec<vectispire_cp_http::routes::RouteEntry> {
    let provisioning = vectispire_cp_access::scim::ScimProvisioning::new(vectispire_cp_access::scim::ScimParts {
        db,
        audit: AccessAudit(audit),
        clock,
        link_privileged,
    });
    vectispire_cp_access::scim_routes(Arc::new(provisioning))
}

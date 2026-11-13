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

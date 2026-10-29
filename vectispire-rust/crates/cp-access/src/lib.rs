//! The control plane's `access` module, `core.access` — who a request is, and what it may see. Phase 1 of the control
//! plane's port (docs/analysis/…_rust_control_plane_port_plan, §7): **accounts and passwords** (task 1.1) — the
//! account rows and views ([`accounts`]), the rules that keep an administrator from locking everybody out
//! ([`account_rules`]), and Argon2id as `PasswordHasher` writes it ([`passwords`]); **the credentials** (task 1.2);
//! and roles and their flags, what a caller may see, the row guards, four-eyes, and who could approve (task 1.5).
//! The second factor's codes ([`totp`]) and the sign-in throttle's arithmetic and keys ([`login_throttle`]) are
//! task 1.3's pure half; its services are [`throttle`] (the counters of `t_login_attempt`), [`second_factor`]
//! (`TotpService`), [`sign_in`] (`AuthService.login`, `AuthenticationFlowService`, `SignInMethodPolicy`),
//! [`rate_windows`] (`RateWindows`, the webhook's shared budget) and [`session_cleanup`] (the `SESSION_CLEANUP` task).
//! The administration services (stage 2b, what the routes of 1.7 call) are [`teams`] (`TeamAdministrationService`,
//! `TeamChannels`), [`account_targets`] (an account's grants), [`api_key_administration`] and [`account_names`]
//! (`AccountNames`, `AccountDirectory`), with their refusals in [`administration`]. Single sign-on (1.4), SCIM and
//! the routes (1.7) land beside them.
//!
//! **A role marker is not authorization** (AGENTS.md, the first trap). The marker half lives in
//! `vectispire-cp-http` ([`Access`](vectispire_cp_http::Access)), because the chain decides it before any module is
//! reached; this crate is the other half — resolving the caller's [`Allowance`] and refusing a row it may not see
//! with a 404 that reads exactly like an absence.
//!
//! The module's places, as `cp-arch-tests` reads them (`layering.rs`): the root files are its API and services
//! ([`accounts`], [`account_rules`], [`passwords`], [`credentials`], [`roles`], [`visibility`], [`rows`],
//! [`four_eyes`], [`approvers`], [`target_grants`]); `internal` the implementation; `persistence` holds every statement; [`security`]
//! is the named interface `access::security` every other module's routes use.

#![forbid(unsafe_code)]

pub mod account_names;
pub mod account_rules;
pub mod account_targets;
pub mod accounts;
pub mod administration;
pub mod api_key_administration;
pub mod approvers;
pub mod credentials;
pub mod four_eyes;
mod internal;
pub mod login_throttle;
pub mod passwords;
mod persistence;
pub mod rate_windows;
pub mod roles;
pub mod rows;
pub mod second_factor;
pub mod security;
pub mod session_cleanup;
pub mod sign_in;
pub mod target_grants;
pub mod teams;
pub mod throttle;
pub mod totp;
pub mod visibility;

pub use approvers::TriageApprovers;
pub use persistence::sign_in::SqlSignInStore;
pub use persistence::{SessionsAndKeys, SqlAccountStore};
pub use roles::{Role, RoleFlags};
pub use rows::NotFound;
pub use security::{CallerScope, CallerVisibility, PrincipalDirectory, PrincipalGrounds};
pub use visibility::{
    AccessError, AccessSettings, AccountRef, Allowance, GrantableTargets, Labels, TargetGrant, VisibilityMode,
    VisibilityService,
};

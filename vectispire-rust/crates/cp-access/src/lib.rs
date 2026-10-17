//! The control plane's `access` module — who a request is, and what it may see. Phase 1 of the control plane's port
//! (docs/analysis/…_rust_control_plane_port_plan, §7): **the credentials** (task 1.2), and roles and their flags, what
//! a caller may see, the row guards, four-eyes, and who could approve (task 1.5). Accounts and passwords (1.1), MFA and
//! throttles (1.3), single sign-on (1.4) and the routes (1.7) land beside them.
//!
//! **A role marker is not authorization** (AGENTS.md, the first trap). The marker half lives in
//! `vectispire-cp-http` ([`Access`](vectispire_cp_http::Access)), because the chain decides it before any module is
//! reached; this crate is the other half — resolving the caller's [`Allowance`] and refusing a row it may not see
//! with a 404 that reads exactly like an absence.
//!
//! The module's places, as `cp-arch-tests` reads them (`layering.rs`): the root files are its API and services
//! ([`credentials`], [`roles`], [`visibility`], [`rows`], [`four_eyes`], [`approvers`]); `internal` the
//! implementation; `persistence` holds every statement; [`security`] is the named interface `access::security`
//! every other module's routes use.

#![forbid(unsafe_code)]

pub mod approvers;
pub mod credentials;
pub mod four_eyes;
mod internal;
mod persistence;
pub mod roles;
pub mod rows;
pub mod security;
pub mod visibility;

pub use approvers::TriageApprovers;
pub use roles::{Role, RoleFlags};
pub use rows::NotFound;
pub use security::{CallerScope, CallerVisibility, PrincipalDirectory};
pub use visibility::{
    AccessError, AccessSettings, AccountRef, Allowance, GrantableTargets, VisibilityMode, VisibilityService,
};

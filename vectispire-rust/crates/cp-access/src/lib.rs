//! The control plane's `access` module — Phase 1, task 1.5 of the port's plan: roles and their flags, what a caller
//! may see, the row guards, four-eyes, and who could approve.
//!
//! **A role marker is not authorization** (AGENTS.md, the first trap). The marker half lives in
//! `vectispire-cp-http` ([`Access`](vectispire_cp_http::Access)), because the chain decides it before any module is
//! reached; this crate is the other half — resolving the caller's [`Allowance`] and refusing a row it may not see
//! with a 404 that reads exactly like an absence.
//!
//! The module's places, as `cp-arch-tests` reads them: the root files are its API and services
//! ([`roles`], [`visibility`], [`rows`], [`four_eyes`], [`approvers`]); `persistence` holds every statement;
//! [`security`] is the named interface `access::security` every other module's routes use. Accounts, credentials,
//! MFA and single sign-on (tasks 1.1–1.4) add their own root files and `persistence` modules beside these.

#![forbid(unsafe_code)]

pub mod approvers;
pub mod four_eyes;
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

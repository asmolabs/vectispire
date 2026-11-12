//! The control plane's settings module — the Rust of `core.settings` and the catalog `common.domain.settings`
//! (plan, Phase 1 task 1.6).
//!
//! - [`Setting`] is the catalog: every key, its type, section, label, help, default and sensitivity, generated
//!   from the Java side's reference file ([`catalog`]), and the rules that decide who may write it —
//!   [`Setting::administrator_only`], [`Setting::governor_only`] — and whether the SOC hears of a change,
//!   [`Setting::governs_security`] ([`rules`]).
//! - [`Setting::validate`] is what a value must look like, in Java's words ([`types`]).
//! - [`Settings`] is the store of `t_setting`: reads with the catalog's defaults, and the conditional writes the
//!   deployment's own rows need between instances — [`Settings::store_internal_if_absent`] and
//!   [`Settings::replace_internal`] — and the safe values a fresh installation is written,
//!   [`Settings::apply_first_install_defaults`].
//! - [`about`] is what the deployment says about itself: its brand, and the version its documents state.

#![forbid(unsafe_code)]

pub mod about;
pub mod catalog;
mod persistence;
pub mod rules;
mod store;
pub mod types;

pub use catalog::{Definition, Setting};
pub use store::{FIRST_INSTALL_DEFAULTS, Settings, SettingsError};
pub use types::{Section, Sensitivity, SettingType, THRESHOLDS};

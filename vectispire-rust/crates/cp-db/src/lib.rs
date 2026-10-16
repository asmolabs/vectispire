//! The control plane's database layer — the Rust side of `spring.datasource`, Spring's transactions,
//! the JPA criteria and `ddl-auto: validate` (plan, task 0.2).
//!
//! - [`Db`] is the pool on MySQL or PostgreSQL, opened with the session the Java drivers open
//!   ([`db`]); [`DbSettings`] reads the `jdbc:` URL operators already write ([`settings`]).
//! - [`Tx`] and [`Mode`] are the transactions; a transaction of its own (`REQUIRES_NEW`) is a second
//!   [`Db::begin`], and [`retry_on_lock_conflict`] retries a unit of work the engine chose as a
//!   deadlock's loser, as the audit log does ([`tx`]).
//! - [`VisibleSelect`] builds the dynamic queries on a target's rows and cannot be built without a
//!   [`Visibility`] ([`query`]).
//! - [`parity::check`] compares declared tables with the schema the migrations built.
//! - [`types`] holds the column types whose mapping is not obvious — the `char(36)` ids above all.
//!
//! **Fixed queries are `sqlx::query!`, checked against both engines** from the two offline caches in
//! `.sqlx/`; see the crate's README for how they are kept.

pub mod db;
pub mod engine;
pub mod parity;
pub mod query;
pub mod settings;
pub mod tx;
pub mod types;
pub mod visibility;

pub use db::{ConnectError, Db};
pub use engine::Engine;
pub use query::{TargetTable, VisibleSelect};
pub use settings::{DatabaseUrl, DbSettings, PoolSettings, Tls};
pub use tx::{LOCK_BACKOFF, LockConflict, Mode, Tx, is_lock_conflict, retry_on_lock_conflict};
pub use visibility::{ScanTarget, Visibility};

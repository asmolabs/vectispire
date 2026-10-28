//! What the control plane runs on, apart from what it does: its configuration under the Java names, its
//! logs, its audit mirror, its meters and actuator answers, its graceful shutdown.
//!
//! The control plane's other crates depend on this one for the things a deployment tells it and the things
//! an operator asks of it — and on none of them for anything else. It holds no framework: the actuator's
//! answers are documents and a status, which the HTTP stack mounts.

#![forbid(unsafe_code)]

pub mod actuator;
pub mod app;
pub mod audit_mirror;
pub mod json;
pub mod metrics;
pub mod property;
pub mod secret_file;
pub mod settings;
pub mod shutdown;
pub mod spring;
pub mod telemetry;

pub use app::{App, Service};
pub use settings::{ConfigError, Settings};

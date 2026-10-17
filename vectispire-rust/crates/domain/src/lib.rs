//! What the agent shares with the control plane as *rules*, not as code.
//!
//! Each module here is a port of a class in `vectispire-common` whose behaviour is part of a
//! contract — a refusal message an operator reads, a kind that decides whether a scan is retried.
//! **The Java class stays the reference.** Where the two must agree byte for byte, a reference set
//! under `vectispire-rust/reference/` holds the Java side's answers and this crate's tests read
//! them (see `README.md`, "The reference sets").

pub mod contract;
pub mod failure;
pub mod net;
pub mod repository_url;
pub mod secret;
pub mod severity;
pub mod sub_path;
pub mod wire;

pub use failure::FailureKind;
pub use severity::Severity;

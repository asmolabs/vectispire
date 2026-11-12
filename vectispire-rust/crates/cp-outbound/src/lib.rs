//! The control plane's outbound door — `PinnedHttpSender`, `OutboundUrlGuard` and what they read.
//!
//! **Every request the control plane makes goes through here**, and nothing else may build an HTTP
//! client: the guard decides what a setting may name, the sender connects to the address that was
//! checked and to no other. A workspace test keeps it so (`onlyTheOutboundDoorSpeaksHttpOutwards`,
//! ported with the boundary tests).
//!
//! The guard's decisions, the reserved endpoints' reading and the address classes are compared with
//! the Java classes' by the reference set under `reference/outbound/`.

#![forbid(unsafe_code)]

pub mod address;
pub mod failure;
pub mod guard;
pub mod pinned_ca;
pub mod policy;
pub mod reserved;
pub mod sender;

pub use failure::OutboundFailure;
pub use guard::{Destination, HostResolver, OutboundUrlGuard, ReservedEndpoint, SystemResolver, UnsafeUrl};
pub use pinned_ca::PinnedCa;
pub use policy::OutboundPolicy;
pub use sender::{Download, Method, PinnedHttpSender, Response};

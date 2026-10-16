//! The agent protocol's contract number — `AgentContract.VERSION` on the Java side.
//!
//! Compared for **strict equality** by the control plane at hello: an agent on another contract
//! is refused with a 409. A Rust agent that is not on the Java agent's number is not a second
//! implementation of one protocol, it is a second protocol.

/// The contract this agent speaks.
pub const VERSION: &str = "1";

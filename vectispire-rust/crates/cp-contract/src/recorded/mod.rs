//! **The recorder's goldens, replayed** — the oracle of the port (plan §4.3, task 2.11). The Java HTTP suite's
//! traffic, recorded by `TrafficRecorder` (`vectispire-java/…/core/golden/`), in the format its README states:
//! `seed` and `effect` rows, identities written as their rank in the test, credentials minted by the test or the
//! server written as placeholders. This module reads that format ([`format`]), makes its placeholders concrete and
//! holds answers to them ([`placeholders`]), reads and writes every table on both engines ([`rows`]), replays a
//! test against a router ([`replay`]) and says which recordings are owed a replay and which wait, with why
//! ([`deferred`]).
//!
//! The older, simpler reader (`golden`) stays for its own tests; nothing the recorder writes is read by it.

pub mod deferred;
pub mod format;
pub mod placeholders;
pub mod replay;
pub mod rows;

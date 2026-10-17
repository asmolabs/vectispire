//! Every route the control plane registers. **None yet**: the HTTP stack (`cp-http`) is built and the
//! modules that give it routes are not. The first route Phase 1 adds is registered here, through the route
//! builder that refuses a route without its requirement and its answer on visibility, and from that day
//! `tests/route_authorization.rs` reads it.

use vectispire_cp_http::routes::{NoVisibility, Routes};

/// The registry, with every module's routes added.
#[must_use]
pub fn routes() -> Routes<()> {
    Routes::new(NoVisibility)
}

//! What the services build on: where a stored connection's requests go ([`targets`]), one path segment
//! ([`ForgePath`](path)), the integrations' registry as forges ask it ([`integrations`]), the probes of a token
//! ([`probes`]), and the discovery's queue, worker and listers.

pub(crate) mod integrations;
pub(crate) mod json;
pub(crate) mod path;
pub(crate) mod probes;
pub(crate) mod targets;

//! Scanner containers through the Docker API — a port of `ContainerRunner`, `ContainerRun` and
//! `ScannerLimits`.
//!
//! **These containers analyse hostile input by definition**: the metadata of an image nobody
//! controls, a repository written by somebody else. Every one is created in one closed shape
//! ([`create_body`]): no capability, no new privilege, a read-only root, scratch space that cannot be
//! executed from, a memory, CPU and process ceiling, no network unless the tool needs one, and a
//! label saying Vectispire started it. That shape is held to what the Java runner sends the daemon,
//! byte for byte, by `reference/container/` — captured off the wire on the Java side.
//!
//! **The daemon is reached through the socket proxy** in every shipped composition
//! (`DOCKER_HOST=tcp://docker-proxy:2375`), which answers only the calls listed in
//! `docker-compose.yml`. Nothing here may call anything else: a call the proxy refuses is a scan that
//! fails in production and passes against a bare daemon.

mod body;
mod limits;
mod run;
mod runner;

pub use body::{SCANNER_LABEL, create_body};
pub use limits::ScannerLimits;
pub use run::{ContainerRun, Mount};
pub use runner::{ContainerResult, ContainerRunner, RunnerError};

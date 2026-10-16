//! Cloning a repository to scan — a port of `GitClone`, `RedirectRefusingConnections` and
//! `CloneFailureException`.
//!
//! **This is where an operator-supplied URL and a private key meet.** The precautions, each with the
//! reason it exists on the Java side:
//!
//! 1. **The URL is checked again here**, although it was checked on entry: rows can predate the
//!    check, and an unchecked URL reaching a clone is code execution (`ext::`) or an SSRF.
//! 2. **No subprocess, hence no shell**: libgit2 in-process, for SSH (libssh2) as for HTTPS (this
//!    crate's own transport, on rustls). A branch name is a branch name, and the image carries no
//!    `git` or `ssh` binary whose configuration could bypass a host-key check.
//! 3. **The private key never touches the file system**: parsed in memory, handed to libssh2 from
//!    memory.
//! 4. **Host keys are pinned or recorded, never trusted silently** ([`HostKeyPolicy`]).
//! 5. **An HTTPS token is sent to its host only, after the forge asks, and no redirect is followed**
//!    ([`https`]).
//!
//! **Choosing libgit2 over gitoxide** (decision of Phase 0 of the port, `README.md`): gitoxide's SSH
//! transport runs the system `ssh`, which the agent's image was built without on purpose and which
//! has had argument-injection advisories; libgit2 with libssh2 checks the host key in-process through
//! a callback, as JGit's database did. The cost — C code, libssh2's OpenSSL for SSH cryptography — is
//! accepted and listed in `deny.toml`. HTTPS does not use libgit2's own stack at all.

mod clone;
mod deploy_key;
mod error;
pub mod https;
mod init;
pub mod known_hosts;

pub use clone::{CloneRequest, HostKeyPolicy, WithoutKey, clone};
pub use error::{CloneError, Kind};
pub use https::HttpsCredential;

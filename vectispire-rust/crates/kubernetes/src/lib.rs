//! The agent's Kubernetes executor — the port of `vectispire-agent`'s `kubernetes` package (decision 0045).
//!
//! On a cluster with no Docker, each [`vectispire_container::ContainerRun`] becomes a pod in a namespace of its own,
//! labelled Pod Security `restricted`, under a Role that reaches nothing else. The workspace goes in, and what the
//! scanner wrote comes out, over `exec`; its standard output is read from a file through a capped read, never from
//! the pod's log, which the kubelet rotates.
//!
//! **Linked by the agent alone.** The control plane holds the key that decrypts every deployment key, and a credential that starts pods beside
//! it would let a compromise of it run arbitrary images in the cluster with the key in hand (0003, 0038, 0045 §1):
//! nothing of `cp-*` reaches this crate, which `crates/agent/tests/isolation.rs` and `deny.toml` hold.
//!
//! **No client library.** What the executor needs is five calls — create, read, list and delete a pod, and `exec`
//! over the `v5.channel.k8s.io` WebSocket protocol — reached with the agent's own HTTP client ([`api`]); the
//! WebSocket framing is written here ([`websocket`]), and the part of the exec protocol that can be got wrong is
//! held apart from the socket ([`channels`]), as Java holds it in `ExecChannels`.
//!
//! **Plugins run here as on Docker.** A bounded output is a memory `emptyDir` of its size, written by the plugin and
//! read back and measured by the holder once it has exited; a registry login is the mounted pull secret's entry for the
//! image's registry, copied in read-only with `DOCKER_CONFIG` naming it, redacted from what the tool and its failures
//! say, and erased after the pod ([`executor`]).
//!
//! **Held to the Java executor by `reference/kubernetes/`**: the pods a run becomes, the probes, the scripts, the
//! address checks, the exec framing, a pod's status read as a failure, the archive brought back, the bounded output's
//! probe and what its answer settles, and the registry login handed over.

pub mod address;
pub mod api;
pub mod archives;
pub mod channels;
pub mod choice;
mod error;
pub mod executor;
mod json;
pub mod pods;
pub mod websocket;

pub use error::KubernetesError;
pub use executor::{HELPER_IMAGE, Isolation, KubernetesExecutor, MatcherCache, Settings};

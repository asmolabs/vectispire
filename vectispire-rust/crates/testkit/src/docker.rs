//! Throwaway containers for the tests that need a real server: a git forge over SSH and HTTPS, the
//! socket proxy, a scanner.
//!
//! **Every name starts with `vs-rs-` and a per-run suffix**, so two runs never share a container
//! and nothing here can reach a deployment's own (`vectispire-*`). Removed on drop, including when
//! the test panics. A missing Docker fails the test: a suite that skips itself reports green
//! without checking anything (AGENTS.md, "Never skip silently").

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// A name no other run uses.
pub fn unique_name(role: &str) -> String {
    format!("vs-rs-{role}-{}-{}", std::process::id(), SEQUENCE.fetch_add(1, Ordering::Relaxed))
}

/// Runs `docker` and returns its standard output, failing the test on a non-zero exit.
pub fn docker(args: &[&str]) -> String {
    let output = Command::new("docker").args(args).output().expect("docker is required by this test");
    assert!(output.status.success(), "docker {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr));
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A container removed with its anonymous volumes when this value is dropped.
#[derive(Debug)]
pub struct Container {
    pub name: String,
}

impl Container {
    /// `docker run -d --name <unique> <args…>`.
    pub fn run(role: &str, args: &[&str]) -> Container {
        let name = unique_name(role);
        let mut full = vec!["run", "-d", "--name", name.as_str(), "--label", "dev.vectispire.test=rust"];
        full.extend_from_slice(args);
        docker(&full);
        Container { name }
    }

    /// The host port Docker published for `container_port` (e.g. `"22/tcp"`).
    pub fn host_port(&self, container_port: &str) -> u16 {
        let mapping = docker(&["port", &self.name, container_port]);
        let first = mapping.lines().next().unwrap_or_default();
        first.rsplit(':').next().unwrap().parse().expect("a published port")
    }

    /// `docker exec` in the container.
    pub fn exec(&self, command: &[&str]) -> String {
        let mut full = vec!["exec", self.name.as_str()];
        full.extend_from_slice(command);
        docker(&full)
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", "-v", &self.name]).output();
    }
}

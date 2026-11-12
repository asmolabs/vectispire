//! The agent holds no database connection and never sees the key that decrypts what the control plane stores —
//! decision 0003's property, from the workspace's side.
//!
//! `crates/agent/tests/isolation.rs` reads the agent's graph for the *drivers, servers and test support* it must
//! not link; its list is the one place those crates are named, and is not repeated here. What it cannot say
//! is the other half, which exists only once the control plane is in the workspace: that nothing the agent links
//! is control-plane code, the crates that read the schema and hold the key. That is this file.
//!
//! The Java build gets both from its module graph (`vectispire-agent` does not depend on `vectispire-core`) and
//! `AgentIsolationTest`.

use crate::graph::Workspace;
use crate::model::{Config, Kind};
use crate::source::read_text;

/// The migration runner reads and writes the schema: control-plane code that is not under the module prefix.
const CONTROL_PLANE_ONLY: &[&str] = &["vectispire-migrate"];

/// The name of the key, assembled so that this file does not name it: the agent's own isolation test fails on
/// any source of the workspace that does.
fn key_name() -> String {
    ["ENCRYPTION", "_KEY"].concat()
}

/// The violations, and how many packages the agent's graph holds, so that a green result can say what it read.
pub fn check(config: &Config, workspace: &Workspace) -> (Vec<String>, usize) {
    let mut violations = Vec::new();
    let Some(linked) = workspace.linked_names("vectispire-agent") else {
        return (vec!["the workspace has no vectispire-agent: the walk has nothing to check".to_owned()], 0);
    };

    for name in &linked {
        let control_plane =
            matches!(config.classify(name), Kind::Module(_) | Kind::Infrastructure(_) | Kind::UnknownControlPlane)
                || CONTROL_PLANE_ONLY.contains(&name.as_str());
        if control_plane {
            violations
                .push(format!("the agent links {name}: control-plane code is never reachable from the agent's binary"));
        }
    }

    // Only the control plane holds the key; the sources of every crate the agent links are held to it.
    let key = key_name();
    for package in workspace.members().filter(|package| linked.contains(&package.name)) {
        for (rel, text) in read_text(&package.dir, &["src", "tests"]) {
            // The agent's own isolation test names the key to look for it, as the one file excused from it.
            if rel == "tests/isolation.rs" {
                continue;
            }
            if text.contains(&key) {
                violations.push(format!(
                    "{}: {rel} names the encryption key: only the control plane holds the key that decrypts deployment keys",
                    package.name
                ));
            }
        }
    }

    violations.sort();
    (violations, linked.len())
}

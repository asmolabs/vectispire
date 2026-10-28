//! A throwaway forge — git over SSH and over HTTPS, with its own certificate authority — built from
//! `crates/testkit/forge/` and started per test (see that directory's `https_forge.py` for its routes).

use crate::docker::{Container, docker};
use std::path::PathBuf;

const IMAGE: &str = "vs-rs-forge:test";

/// A running forge and what a test needs from it.
#[derive(Debug)]
pub struct Forge {
    pub container: Container,
    pub ssh_port: u16,
    pub https_port: u16,
    /// The token the HTTPS side accepts — random per forge, so no test file holds one.
    pub token: String,
    /// The authority that signed the HTTPS certificate, PEM.
    pub ca_pem: String,
    /// The deployment key the SSH side accepts, and one it does not.
    pub deploy_key: String,
    pub other_key: String,
    /// The same forge's other accepted keys: RSA (OpenSSH and PEM encodings) and ECDSA.
    pub rsa_key: String,
    pub rsa_pem_key: String,
    pub ecdsa_key: String,
    /// The server's ed25519 host key: `ssh-ed25519 AAAA…`.
    pub host_key: String,
}

impl Forge {
    pub fn start() -> Forge {
        let context = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("forge");
        docker(&["build", "-q", "-t", IMAGE, &context.display().to_string()]);
        let token: String = (0..4).map(|_| format!("{:08x}", random_u32())).collect();
        let variable = format!("FORGE_TOKEN={token}");
        let container =
            Container::run("forge", &["-e", &variable, "-p", "127.0.0.1::22", "-p", "127.0.0.1::443", IMAGE]);
        for _ in 0..200 {
            if std::process::Command::new("docker")
                .args(["exec", &container.name, "test", "-f", "/certs/ready"])
                .output()
                .is_ok_and(|output| output.status.success())
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let read = |path: &str| container.exec(&["cat", path]) + "\n";
        let host_key = container.exec(&["cat", "/etc/ssh/ssh_host_ed25519_key.pub"]);
        let host_key = host_key.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        Forge {
            ssh_port: container.host_port("22/tcp"),
            https_port: container.host_port("443/tcp"),
            token,
            ca_pem: read("/certs/ca.pem"),
            deploy_key: read("/keys/deploy"),
            other_key: read("/keys/other"),
            rsa_key: read("/keys/rsa"),
            rsa_pem_key: read("/keys/rsa-pem"),
            ecdsa_key: read("/keys/ecdsa"),
            host_key,
            container,
        }
    }

    /// `ssh://git@localhost:<port>/srv/git/<path>`.
    pub fn ssh_url(&self, path: &str) -> String {
        format!("ssh://git@localhost:{}/srv/git/{path}", self.ssh_port)
    }

    /// `https://localhost:<port>/<path>`.
    pub fn https_url(&self, path: &str) -> String {
        format!("https://localhost:{}/{path}", self.https_port)
    }

    /// The requests the HTTPS side received, one line each: `GET /path auth=none|token|other`.
    pub fn requests(&self) -> Vec<String> {
        self.container.exec(&["cat", "/tmp/requests.log"]).lines().map(str::to_owned).collect()
    }
}

/// Randomness for a test token, without a dependency: the hasher's per-process random keys.
fn random_u32() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64),
    );
    hasher.finish() as u32
}

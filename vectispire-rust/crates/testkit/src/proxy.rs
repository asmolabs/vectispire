//! The socket proxy as the shipped composition configures it — `docker-compose.yml`'s
//! `docker-proxy` service, same image digest, same allowlist — on a loopback port.

use crate::docker::Container;

/// `tecnativa/docker-socket-proxy`, pinned as `docker-compose.yml` pins it.
pub const IMAGE: &str =
    "tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2";

/// What `ContainerRunner` calls, and nothing else — the composition's environment, line for line.
const ALLOWED: [&str; 6] = ["PING=1", "VERSION=1", "INFO=1", "CONTAINERS=1", "IMAGES=1", "POST=1"];
const REFUSED: [&str; 16] = [
    "EXEC=0",
    "AUTH=0",
    "SECRETS=0",
    "CONFIGS=0",
    "SWARM=0",
    "NODES=0",
    "SERVICES=0",
    "TASKS=0",
    "VOLUMES=0",
    "NETWORKS=0",
    "PLUGINS=0",
    "SYSTEM=0",
    "DISTRIBUTION=0",
    "BUILD=0",
    "COMMIT=0",
    "SESSION=0",
];

/// A running proxy and the `tcp://` address the runner reaches it at.
#[derive(Debug)]
pub struct SocketProxy {
    pub container: Container,
    pub address: String,
}

impl SocketProxy {
    pub fn start() -> SocketProxy {
        let mut args: Vec<String> = vec![
            "-p".into(),
            "127.0.0.1::2375".into(),
            "-v".into(),
            "/var/run/docker.sock:/var/run/docker.sock:ro".into(),
        ];
        for variable in ALLOWED.iter().chain(REFUSED.iter()) {
            args.push("-e".into());
            args.push((*variable).into());
        }
        args.push(IMAGE.into());
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let container = Container::run("proxy", &borrowed);
        let address = format!("tcp://127.0.0.1:{}", container.host_port("2375/tcp"));
        // The proxy is HAProxy: it answers once it has read its configuration.
        for _ in 0..50 {
            if std::net::TcpStream::connect(address.trim_start_matches("tcp://")).is_ok() {
                std::thread::sleep(std::time::Duration::from_millis(300));
                return SocketProxy { container, address };
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("the socket proxy did not start");
    }
}

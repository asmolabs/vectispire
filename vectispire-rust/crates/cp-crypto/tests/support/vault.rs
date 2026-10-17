//! A stub of Vault's Transit engine on loopback: it answers by path prefix and keeps every request it read.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use vectispire_cp_crypto::VaultDoor;
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_tls::TlsTrust;

/// What the stub read: the method, the path, the headers (names lower-cased) and the body.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }
}

pub struct Stub {
    pub port: u16,
    pub requests: Arc<Mutex<Vec<Request>>>,
}

impl Stub {
    /// `answers`: a path prefix, a status and a body, the first matching prefix answering; 404 otherwise.
    pub async fn start(answers: Vec<(&'static str, u16, String)>) -> Stub {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = requests.clone();
        let answers = Arc::new(answers);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let (log, answers) = (log.clone(), answers.clone());
                tokio::spawn(async move {
                    let request = read(&mut stream).await;
                    let (status, body) = answers
                        .iter()
                        .find(|(prefix, _, _)| request.path.starts_with(prefix))
                        .map(|(_, status, body)| (*status, body.clone()))
                        .unwrap_or((404, "{\"errors\":[]}".to_owned()));
                    log.lock().unwrap().push(request);
                    let reply = format!(
                        "HTTP/1.1 {status} Stub\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Stub { port, requests }
    }

    pub fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

async fn read(stream: &mut tokio::net::TcpStream) -> Request {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break buffer.len();
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_owned();
    let path = first.next().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_lowercase(), value.trim().to_owned()))
        .collect();
    let length = headers.iter().find(|(name, _)| name == "content-length").map_or(0, |(_, v)| v.parse().unwrap_or(0));
    let mut body = buffer[end..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Request { method, path, headers, body: String::from_utf8_lossy(&body).into_owned() }
}

/// The door as the product builds it: the sender, and a guard with no reserved endpoint.
pub fn door() -> VaultDoor {
    VaultDoor { sender: PinnedHttpSender::new(TlsTrust::BuiltIn), guard: OutboundUrlGuard::new(Vec::new()) }
}

/// The door with `port` reserved on every host, as the control plane reserves its own.
pub fn reserved_door(port: u16) -> VaultDoor {
    VaultDoor {
        sender: PinnedHttpSender::new(TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(vec![vectispire_cp_outbound::ReservedEndpoint::on_every_host(
            i32::from(port),
            "the control plane itself",
        )]),
    }
}

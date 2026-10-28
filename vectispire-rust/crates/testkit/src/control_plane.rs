//! A stub control plane on a loopback port: every request recorded, every answer the test's.
//!
//! Plain HTTP over `std::net`, one thread per connection, each answer closing its connection — so a
//! handler may block (a long poll that holds, a scan that waits for a signal) without holding up the
//! others, and a request the client sends is always seen whole before it is answered.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// A request as it arrived.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// The path and the query, as sent: `/api/v1/agent/jobs?wait=1`.
    pub target: String,
    /// Names lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The path without its query.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or_default()
    }

    /// `METHOD /path`, the query left out — how a test names a route.
    pub fn route(&self) -> String {
        format!("{} {}", self.method, self.path())
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_lowercase();
        self.headers.iter().find(|(header, _)| *header == name).map(|(_, value)| value.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// An answer.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn status(status: u16) -> Response {
        Response { status, headers: Vec::new(), body: String::new() }
    }

    pub fn json(status: u16, body: serde_json::Value) -> Response {
        Response { status, headers: Vec::new(), body: body.to_string() }
    }

    pub fn text(status: u16, body: impl Into<String>) -> Response {
        Response { status, headers: Vec::new(), body: body.into() }
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Response {
        self.headers.push((name.to_owned(), value.into()));
        self
    }
}

type Handler = dyn Fn(&Request) -> Response + Send + Sync;

/// The stub. Dropping it stops accepting; a connection already open is answered.
pub struct StubControlPlane {
    url: String,
    seen: Arc<Mutex<Vec<Request>>>,
    stopped: Arc<AtomicBool>,
    port: u16,
}

impl std::fmt::Debug for StubControlPlane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("StubControlPlane").field("url", &self.url).finish()
    }
}

impl StubControlPlane {
    /// Answers every request with `handler`'s answer.
    pub fn start(handler: impl Fn(&Request) -> Response + Send + Sync + 'static) -> StubControlPlane {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(handler);
        let (recorded, stopping) = (seen.clone(), stopped.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let (handler, recorded) = (handler.clone(), recorded.clone());
                std::thread::spawn(move || serve(stream, &*handler, &recorded));
            }
        });
        StubControlPlane { url: format!("http://127.0.0.1:{port}"), seen, stopped, port }
    }

    /// Answers the requests in order with `answers`, then 500.
    pub fn answering(answers: Vec<Response>) -> StubControlPlane {
        let queue = Mutex::new(std::collections::VecDeque::from(answers));
        StubControlPlane::start(move |_| {
            queue.lock().unwrap().pop_front().unwrap_or_else(|| Response::text(500, "no answer left"))
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Every request received so far, in the order each was read whole.
    pub fn requests(&self) -> Vec<Request> {
        self.seen.lock().unwrap().clone()
    }

    /// The routes received so far — `METHOD /path`.
    pub fn routes(&self) -> Vec<String> {
        self.requests().iter().map(Request::route).collect()
    }
}

impl Drop for StubControlPlane {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        // Wakes the accept loop so it sees the flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn serve(stream: TcpStream, handler: &Handler, recorded: &Mutex<Vec<Request>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else { return };
    let (method, target) = (method.to_owned(), target.to_owned());
    let mut headers = Vec::new();
    let mut length = 0;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.trim().split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap_or(0);
            }
            headers.push((name.trim().to_lowercase(), value.trim().to_owned()));
        }
    }
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let request = Request { method, target, headers, body };
    recorded.lock().unwrap().push(request.clone());
    let response = handler(&request);
    let extra: String = response.headers.iter().map(|(name, value)| format!("{name}: {value}\r\n")).collect();
    let content_type = if response.body.is_empty() { "" } else { "Content-Type: application/json\r\n" };
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {} Stub\r\n{content_type}Content-Length: {}\r\nConnection: close\r\n{extra}\r\n{}",
        response.status,
        response.body.len(),
        response.body
    );
    let _ = stream.flush();
}

//! The five calls the Kubernetes executor makes to the API server (`KubernetesApi`): create, read, list and delete a
//! pod, and `exec` in one — over the agent's own HTTP client, with no client library (decision 0045 §1).
//!
//! **Redirects are refused**, as for the control plane: the API server is a fixed address, and following a redirect
//! would carry the service account's token to a host nobody declared. **The token is read again on every call**: a
//! projected service-account token is rotated by the kubelet while the agent runs, and one read at start expires under
//! it. **The cluster's authority alone is trusted**: the CA the pod is handed, never the agent's other trust.

use crate::channels::{self, ExecChannels};
use crate::websocket::{self, Event, Reader};
use crate::{KubernetesError, address, json};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, mpsc};
use vectispire_domain::secret::Secret;
use vectispire_tls::TlsTrust;

/// The one subprotocol spoken: v4 cannot say "standard input is finished", and `tar` waits for it.
pub const EXEC_PROTOCOL: &str = "v5.channel.k8s.io";

const SERVICE_ACCOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Where the bearer token comes from: the service account's file, read at every call, or a fixed one (the tests').
#[derive(Clone)]
enum Token {
    File(PathBuf),
    Fixed(Secret),
}

/// What a command wrote and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: String,
    /// Its exit code, or -1 when `over_ceiling`.
    pub exit_code: i32,
    /// Standard output passed the ceiling, and was not read to its end: a failure, never a report to parse.
    pub over_ceiling: bool,
}

/// The API server.
#[derive(Clone)]
pub struct KubernetesApi {
    server: String,
    token: Arc<Token>,
    client: reqwest::Client,
}

impl std::fmt::Debug for KubernetesApi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("KubernetesApi").field("server", &self.server).finish_non_exhaustive()
    }
}

impl KubernetesApi {
    /// The API server of the cluster the agent runs in, as its pod sees it: the address Kubernetes puts in its
    /// environment — refused unless it is the `kubernetes.default.svc` service's ([`address::of`]) — the token and the
    /// authority it mounts.
    pub fn in_cluster() -> Result<KubernetesApi, String> {
        // Checked against the cluster's DNS before the token goes anywhere: the environment can be overridden.
        let server = address::from_environment()?;
        let account = Path::new(SERVICE_ACCOUNT);
        let trust = trusting(&account.join("ca.crt"))?;
        KubernetesApi::new(&server.uri(), Token::File(account.join("token")), &trust)
    }

    /// An API server reached with a fixed token: `server` is its `https` address, with no path.
    pub fn with_token(server: &str, token: Secret, trust: &TlsTrust) -> Result<KubernetesApi, String> {
        KubernetesApi::new(server, Token::Fixed(token), trust)
    }

    fn new(server: &str, token: Token, trust: &TlsTrust) -> Result<KubernetesApi, String> {
        let Some(rest) = server.strip_prefix("https://") else {
            // The token is a credential: it does not travel in the clear, whatever the configuration says.
            let scheme = server.split_once(':').map_or(server, |(scheme, _)| scheme);
            return Err(format!("The API server is reached over https, not {scheme}."));
        };
        let client = trust
            .client()
            .https_only(true)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|error| format!("The client of the API server could not be built: {error}"))?;
        Ok(KubernetesApi { server: format!("https://{}", rest.trim_end_matches('/')), token: Arc::new(token), client })
    }

    fn bearer(&self) -> Result<String, KubernetesError> {
        match self.token.as_ref() {
            Token::Fixed(token) => Ok(format!("Bearer {}", token.expose())),
            Token::File(path) => std::fs::read_to_string(path)
                .map(|token| format!("Bearer {}", vectispire_domain::java::strip(&token)))
                .map_err(|error| {
                    KubernetesError::unanswered(format!("The service account token could not be read: {error}"))
                }),
        }
    }

    /// Creates `pod` in `namespace` and returns it as the API server stored it.
    pub async fn create_pod(&self, namespace: &str, pod: &Value) -> Result<Value, KubernetesError> {
        let path = pods_path(namespace)?;
        Ok(self.call(reqwest::Method::POST, &path, Some(pod), &[201]).await?.unwrap_or(Value::Null))
    }

    /// Asks whether `pod` would be admitted, creating nothing (`dryRun=All`: admission runs, the object is not
    /// stored). The `create` verb the Role holds is all it needs. An error carries the API server's refusal.
    pub async fn create_pod_dry_run(&self, namespace: &str, pod: &Value) -> Result<(), KubernetesError> {
        let path = format!("{}?dryRun=All", pods_path(namespace)?);
        self.call(reqwest::Method::POST, &path, Some(pod), &[201, 200]).await.map(|_| ())
    }

    /// The pod, or `None` when there is none of that name.
    pub async fn pod(&self, namespace: &str, name: &str) -> Result<Option<Value>, KubernetesError> {
        let path = format!("{}/{}", pods_path(namespace)?, segment(name)?);
        self.call(reqwest::Method::GET, &path, None, &[200]).await
    }

    /// The pods carrying `label_selector`, in Kubernetes' selector syntax.
    pub async fn pods(&self, namespace: &str, label_selector: &str) -> Result<Vec<Value>, KubernetesError> {
        let path = format!("{}?labelSelector={}", pods_path(namespace)?, query(label_selector));
        let list = self.call(reqwest::Method::GET, &path, None, &[200]).await?.unwrap_or(Value::Null);
        Ok(json::children(json::path(Some(&list), "items")).into_iter().cloned().collect())
    }

    /// Deletes the pod at once, with no grace period: a scanner has nothing to save. An absent pod is not an error.
    pub async fn delete_pod(&self, namespace: &str, name: &str) -> Result<(), KubernetesError> {
        let path = format!("{}/{}?gracePeriodSeconds=0", pods_path(namespace)?, segment(name)?);
        self.call(reqwest::Method::DELETE, &path, None, &[200, 202]).await.map(|_| ())
    }

    /// Deletes every pod carrying `label_selector` — what a crash of the agent left behind.
    pub async fn delete_pods(&self, namespace: &str, label_selector: &str) -> Result<(), KubernetesError> {
        let path = format!("{}?gracePeriodSeconds=0&labelSelector={}", pods_path(namespace)?, query(label_selector));
        self.call(reqwest::Method::DELETE, &path, None, &[200, 202]).await.map(|_| ())
    }

    /// The first `limit_bytes` of a container's log — a diagnostic, never a report: the kubelet rotates logs, so what
    /// is read here may be cut, and nothing parses it (decision 0045 §4).
    pub async fn log(
        &self,
        namespace: &str,
        pod: &str,
        container: &str,
        limit_bytes: u64,
    ) -> Result<String, KubernetesError> {
        let path = format!(
            "{}/{}/log?container={}&limitBytes={limit_bytes}",
            pods_path(namespace)?,
            segment(pod)?,
            query(container)
        );
        let response = self
            .client
            .get(format!("{}{path}", self.server))
            .timeout(CALL_TIMEOUT)
            .header("Authorization", self.bearer()?)
            .send()
            .await
            .map_err(unreachable)?;
        let status = response.status().as_u16();
        let body = response.text().await.map_err(unreachable)?;
        if status != 200 {
            return Err(KubernetesError::new(
                format!("GET {} answered HTTP {status}: {}", without_query(&path), excerpt(&body)),
                status,
            ));
        }
        Ok(body)
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
        expected: &[u16],
    ) -> Result<Option<Value>, KubernetesError> {
        let mut request = self
            .client
            .request(method.clone(), format!("{}{path}", self.server))
            .timeout(CALL_TIMEOUT)
            .header("Authorization", self.bearer()?)
            .header("Accept", "application/json");
        if let Some(body) = body {
            request = request.header("Content-Type", "application/json").body(body.to_string());
        }
        let response = request.send().await.map_err(unreachable)?;
        let status = response.status().as_u16();
        let text = response.text().await.map_err(unreachable)?;
        if expected.contains(&status) {
            return parse(&text).map(Some);
        }
        if status == 404 && method != reqwest::Method::POST {
            return Ok(None);
        }
        Err(KubernetesError::new(
            format!("{method} {} answered HTTP {status}: {}", without_query(path), excerpt(&text)),
            status,
        ))
    }

    /// Runs `command` in `container` of a running pod, with `stdin`'s chunks as its standard input when given, and
    /// returns what it wrote into `channels`.
    ///
    /// Standard input is sent and then *closed* — v5's close signal — so a `tar -x` reading it ends. Standard output
    /// stops being read past the channels' ceiling: the result then says [`ExecResult::over_ceiling`] and carries no
    /// exit code. An error when the server refuses the exec, the command cannot start, or the timeout passes — never a
    /// result that would be read as the command's own.
    pub async fn exec(
        &self,
        target: (&str, &str, &str),
        command: &[String],
        stdin: Option<mpsc::Receiver<Vec<u8>>>,
        mut channels: ExecChannels,
        timeout: Duration,
    ) -> Result<ExecResult, KubernetesError> {
        let (namespace, pod, container) = target;
        let deadline = Instant::now().checked_add(timeout).unwrap_or_else(Instant::now);
        let mut path = format!(
            "{}/{}/exec?container={}&stdout=true&stderr=true",
            pods_path(namespace)?,
            segment(pod)?,
            query(container)
        );
        if stdin.is_some() {
            path.push_str("&stdin=true");
        }
        for argument in command {
            path.push_str("&command=");
            path.push_str(&query(argument));
        }
        let shown = java_duration(timeout);
        let key = websocket::key();
        let request = self
            .client
            .get(format!("{}{path}", self.server))
            .header("Authorization", self.bearer()?)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", &key)
            .header("Sec-WebSocket-Protocol", EXEC_PROTOCOL);
        let response = match tokio::time::timeout(remaining(deadline), request.send()).await {
            Err(_) => {
                return Err(KubernetesError::unanswered(format!(
                    "The exec in {pod}/{container} was not opened within {shown}."
                )));
            }
            Ok(Err(error)) => {
                return Err(KubernetesError::unanswered(format!(
                    "The exec in {pod}/{container} could not be opened: {error}"
                )));
            }
            Ok(Ok(response)) => response,
        };
        let status = response.status().as_u16();
        if status != 101 {
            let body = response.text().await.unwrap_or_default();
            return Err(KubernetesError::new(
                format!("The exec in {pod}/{container} was refused: HTTP {status} {}", excerpt(&body)),
                status,
            ));
        }
        let header = |name: &str| {
            response.headers().get(name).and_then(|value| value.to_str().ok()).unwrap_or_default().to_owned()
        };
        handshake(
            &format!("{pod}/{container}"),
            &key,
            &header("Sec-WebSocket-Accept"),
            &header("Sec-WebSocket-Protocol"),
        )?;
        let upgraded = response.upgrade().await.map_err(|error| {
            KubernetesError::unanswered(format!("The exec in {pod}/{container} could not be opened: {error}"))
        })?;
        let (input, output) = tokio::io::split(upgraded);
        let output = Arc::new(Mutex::new(output));
        let mut reader = Reader::new(input);

        let exchanged = {
            let reading = read_all(&mut reader, &mut channels, output.clone());
            let writing = write_all(stdin, output.clone());
            tokio::pin!(reading);
            tokio::pin!(writing);
            let mut written = false;
            let exchange = async {
                loop {
                    tokio::select! {
                        read = &mut reading => break read,
                        sent = &mut writing, if !written => {
                            written = true;
                            if let Err(broken) = sent {
                                break Err(broken);
                            }
                        }
                    }
                }
            };
            tokio::time::timeout(remaining(deadline), exchange).await
        };
        match exchanged {
            Err(_) => {
                return Err(KubernetesError::unanswered(format!(
                    "The exec in {pod}/{container} did not end within {shown}."
                )));
            }
            Ok(Err(broken)) => {
                return Err(KubernetesError::unanswered(format!("The exec in {pod}/{container} broke: {broken}")));
            }
            Ok(Ok(())) => {}
        }
        channels
            .flush()
            .map_err(|broken| KubernetesError::unanswered(format!("The exec in {pod}/{container} broke: {broken}")))?;
        if channels.over_ceiling() {
            return Ok(ExecResult {
                stdout: channels.take_stdout(),
                stderr: channels.stderr(),
                exit_code: -1,
                over_ceiling: true,
            });
        }
        let exit_code = channels.exit_code()?.ok_or_else(|| {
            KubernetesError::unanswered(format!(
                "The exec in {pod}/{container} ended with no status: the command's end was not reported."
            ))
        })?;
        Ok(ExecResult { stdout: channels.take_stdout(), stderr: channels.stderr(), exit_code, over_ceiling: false })
    }
}

/// The server's answer to the handshake: the key answered — a server, or a proxy, that did not compute it is not
/// speaking WebSocket to this client — and the one subprotocol spoken, without which standard input cannot be closed.
fn handshake(exec: &str, key: &str, accept: &str, protocol: &str) -> Result<(), KubernetesError> {
    if accept != websocket::accept_for(key) {
        return Err(KubernetesError::unanswered(format!(
            "The exec in {exec} could not be opened: the API server's handshake did not answer it."
        )));
    }
    if protocol != EXEC_PROTOCOL {
        return Err(KubernetesError::unanswered(format!(
            "The API server does not speak {EXEC_PROTOCOL} (it answered \"{protocol}\"): Kubernetes 1.30 or later is \
             required."
        )));
    }
    Ok(())
}

type Output = Arc<Mutex<tokio::io::WriteHalf<reqwest::Upgraded>>>;

/// Every frame until the server closes, the stream ends, or standard output passes its ceiling.
async fn read_all(
    reader: &mut Reader<tokio::io::ReadHalf<reqwest::Upgraded>>,
    channels: &mut ExecChannels,
    output: Output,
) -> std::io::Result<()> {
    while let Some(event) = reader.next().await? {
        match event {
            Event::Data { binary: true, chunk, last } => {
                if !channels.accept(&chunk, last)? {
                    return Ok(());
                }
            }
            // The exec protocol speaks binary; a text message is not one of its channels.
            Event::Data { binary: false, .. } => {}
            Event::Ping(payload) => {
                output.lock().await.write_all(&websocket::client_frame(websocket::PONG, &payload)).await?;
            }
            Event::Close => return Ok(()),
        }
    }
    Ok(())
}

/// Standard input, chunk by chunk, then v5's close of the channel. Nothing to send without it.
async fn write_all(stdin: Option<mpsc::Receiver<Vec<u8>>>, output: Output) -> std::io::Result<()> {
    let Some(mut stdin) = stdin else { return std::future::pending().await };
    while let Some(chunk) = stdin.recv().await {
        let mut payload = Vec::with_capacity(chunk.len().saturating_add(1));
        payload.push(channels::STDIN);
        payload.extend_from_slice(&chunk);
        let frame = websocket::client_frame(websocket::BINARY, &payload);
        let mut output = output.lock().await;
        output.write_all(&frame).await?;
        output.flush().await?;
    }
    let mut output = output.lock().await;
    output.write_all(&websocket::client_frame(websocket::BINARY, &[channels::CLOSE, channels::STDIN])).await?;
    output.flush().await
}

/// A TLS trust of `bundle`'s certificates alone — the cluster's authority, and no other.
pub fn trusting(bundle: &Path) -> Result<TlsTrust, String> {
    TlsTrust::from_bundle(bundle)
        .map_err(|error| format!("The API server's authority could not be read from {}: {error}", bundle.display()))
}

fn unreachable(error: reqwest::Error) -> KubernetesError {
    KubernetesError::unanswered(format!("The API server is unreachable: {error}"))
}

fn parse(text: &str) -> Result<Value, KubernetesError> {
    if vectispire_domain::java::is_blank(text) {
        return Ok(Value::Null);
    }
    json::read_tree(text.as_bytes()).ok_or_else(|| {
        KubernetesError::unanswered(format!("The API server answered something that is not JSON: {}", excerpt(text)))
    })
}

/// The server's own message when its answer is a Status, otherwise the start of what it said.
fn excerpt(body: &str) -> String {
    if let Some(document) = json::read_tree(body.as_bytes()) {
        let message = json::text_or(json::path(Some(&document), "message"), "");
        if !message.is_empty() {
            return message;
        }
    }
    body.chars().take(300).collect()
}

fn without_query(path: &str) -> &str {
    path.split_once('?').map_or(path, |(path, _)| path)
}

fn pods_path(namespace: &str) -> Result<String, KubernetesError> {
    Ok(format!("/api/v1/namespaces/{}/pods", segment(namespace)?))
}

/// A name in a path: Kubernetes names are DNS labels — `[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?` — so anything else is
/// refused rather than escaped.
pub fn segment(name: &str) -> Result<&str, KubernetesError> {
    let alphanumeric = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let bytes = name.as_bytes();
    let valid = (1..=253).contains(&bytes.len())
        && bytes.first().is_some_and(alphanumeric)
        && bytes.last().is_some_and(alphanumeric)
        && bytes.iter().all(|byte| alphanumeric(byte) || *byte == b'-' || *byte == b'.');
    if valid { Ok(name) } else { Err(KubernetesError::unanswered(format!("Not a Kubernetes name: \"{name}\"."))) }
}

/// `URLEncoder.encode(value, UTF_8)` with `+` written `%20`: letters, digits and `.-*_` as they are, every other byte
/// percent-encoded in upper case.
pub fn query(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'*' | b'_') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// What is left before `deadline` — never zero, as a timeout is a duration, not a moment.
fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1))
}

/// `Duration.toString`, for the messages Java writes with it: `PT5M`, `PT1M30S`, `PT0.5S`.
pub fn java_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let (hours, minutes, seconds) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    let millis = duration.subsec_millis();
    let mut text = String::from("PT");
    if hours > 0 {
        text.push_str(&format!("{hours}H"));
    }
    if minutes > 0 {
        text.push_str(&format!("{minutes}M"));
    }
    if seconds > 0 || millis > 0 || text == "PT" {
        if millis > 0 {
            let fraction = format!("{millis:03}");
            text.push_str(&format!("{seconds}.{}S", fraction.trim_end_matches('0')));
        } else {
            text.push_str(&format!("{seconds}S"));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_queries_are_written_as_the_java_client_writes_them() {
        assert_eq!(query("vectispire.dev/agent=a b"), "vectispire.dev%2Fagent%3Da%20b");
        assert_eq!(query("sh -c 'é'"), "sh%20-c%20%27%C3%A9%27");
        assert_eq!(query("a*b_c.d-e"), "a*b_c.d-e");
        assert!(segment("vs-gitleaks-0102030405").is_ok());
        for refused in ["", "-a", "a-", "A", "a/b", "a..b/", &"a".repeat(254)] {
            assert!(segment(refused).is_err(), "{refused:?}");
        }
        assert!(segment(&"a".repeat(253)).is_ok());
    }

    #[test]
    fn durations_read_as_java_writes_them() {
        assert_eq!(java_duration(Duration::from_secs(300)), "PT5M");
        assert_eq!(java_duration(Duration::from_secs(90)), "PT1M30S");
        assert_eq!(java_duration(Duration::from_secs(3600)), "PT1H");
        assert_eq!(java_duration(Duration::from_secs(3725)), "PT1H2M5S");
        assert_eq!(java_duration(Duration::ZERO), "PT0S");
        assert_eq!(java_duration(Duration::from_millis(1500)), "PT1.5S");
    }

    #[test]
    fn the_token_never_travels_in_the_clear() {
        let refused = KubernetesApi::with_token("http://10.0.0.1:6443", Secret::new("t"), &TlsTrust::BuiltIn);
        assert_eq!(refused.unwrap_err(), "The API server is reached over https, not http.");
    }

    /// The handshake is believed only when it answers this client's key, in the one subprotocol spoken.
    #[test]
    fn the_handshake_must_answer_the_key_in_the_subprotocol() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let answer = websocket::accept_for(key);
        assert!(handshake("p/c", key, &answer, EXEC_PROTOCOL).is_ok());
        let wrong = handshake("p/c", key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo", EXEC_PROTOCOL).unwrap_err();
        assert_eq!(wrong.message, "The exec in p/c could not be opened: the API server's handshake did not answer it.");
        let old = handshake("p/c", key, &answer, "v4.channel.k8s.io").unwrap_err();
        assert!(old.message.contains("(it answered \"v4.channel.k8s.io\"): Kubernetes 1.30 or later"), "{old}");
        assert!(handshake("p/c", key, &answer, "").is_err());
    }

    #[test]
    fn an_answer_s_excerpt_is_its_status_message_or_its_start() {
        assert_eq!(excerpt(r#"{"kind":"Status","message":"pods \"x\" is forbidden"}"#), "pods \"x\" is forbidden");
        assert_eq!(excerpt(&"x".repeat(400)).len(), 300);
        assert_eq!(excerpt("{\"message\": 5}"), "5");
        assert_eq!(without_query("/a/b?c=d"), "/a/b");
    }
}

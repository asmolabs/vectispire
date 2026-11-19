//! What the API server sends back on an `exec` WebSocket, sorted by channel — the part of the `v5.channel.k8s.io`
//! protocol that is ours to get right, kept apart from the socket so it is tested without one (`ExecChannels`).
//!
//! Every message starts with one byte naming its channel: 1 standard output, 2 standard error, 3 the status the server
//! writes once the command has ended. **Only the first fragment of a message carries it**: a large message arrives in
//! pieces, and reading the first byte of every piece as a channel would scatter a report across stderr and the status.
//!
//! **Standard output has a ceiling, and passing it is said, never hidden.** What is read is a scanner's report; a
//! report cut at the ceiling and parsed leniently is the absent-versus-empty defect (decision 0007), so the caller is
//! told [`ExecChannels::over_ceiling`] and fails the step. Standard error is a diagnostic, kept to its first
//! [`STDERR_BYTES`] and no more.
//!
//! Held to Java by `reference/kubernetes/exec-channels.json`.

use crate::{KubernetesError, json};
use std::io::Write;

pub const STDIN: u8 = 0;
pub const STDOUT: u8 = 1;
pub const STDERR: u8 = 2;
pub const STATUS: u8 = 3;
/// v5's signal: the next byte names a channel the client has finished writing to.
pub const CLOSE: u8 = 255;

/// What standard error keeps.
pub const STDERR_BYTES: usize = 64 * 1024;
/// A status is a small JSON document; one past this is not one.
const STATUS_BYTES: usize = 64 * 1024;

/// One exec's channels, filled fragment by fragment.
pub struct ExecChannels {
    ceiling: u64,
    /// Standard output streamed elsewhere — a tree copied back is too large to hold — or kept in `stdout`.
    sink: Option<Box<dyn Write + Send>>,
    stdout: Vec<u8>,
    stdout_bytes: u64,
    stderr: Vec<u8>,
    status: Vec<u8>,
    at_message_start: bool,
    channel: Option<u8>,
    over_ceiling: bool,
}

impl std::fmt::Debug for ExecChannels {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecChannels")
            .field("ceiling", &self.ceiling)
            .field("stdout_bytes", &self.stdout_bytes)
            .field("over_ceiling", &self.over_ceiling)
            .finish_non_exhaustive()
    }
}

impl ExecChannels {
    /// Standard output kept in memory, for [`ExecChannels::stdout`].
    pub fn new(ceiling: u64) -> ExecChannels {
        ExecChannels {
            ceiling,
            sink: None,
            stdout: Vec::new(),
            stdout_bytes: 0,
            stderr: Vec::new(),
            status: Vec::new(),
            at_message_start: true,
            channel: None,
            over_ceiling: false,
        }
    }

    /// Standard output written to `sink` as it comes, and never more than the ceiling and the one byte that proves it
    /// was passed.
    pub fn to_sink(sink: Box<dyn Write + Send>, ceiling: u64) -> ExecChannels {
        ExecChannels { sink: Some(sink), ..ExecChannels::new(ceiling) }
    }

    /// One fragment of a message, as the socket delivered it. `Ok(false)` once standard output has passed its
    /// ceiling: the caller stops reading. An error is a sink that refused a write — the copy is broken, and said so
    /// rather than left half-made.
    pub fn accept(&mut self, fragment: &[u8], last: bool) -> std::io::Result<bool> {
        let mut body = fragment;
        if self.at_message_start
            && let Some((channel, rest)) = fragment.split_first()
        {
            self.channel = Some(*channel);
            self.at_message_start = false;
            body = rest;
        }
        match self.channel {
            Some(STDOUT) => {
                let room = self.ceiling.saturating_add(1).saturating_sub(self.stdout_bytes);
                let take = usize::try_from(room).unwrap_or(usize::MAX).min(body.len());
                let kept = body.get(..take).unwrap_or_default();
                match &mut self.sink {
                    Some(sink) => sink.write_all(kept)?,
                    None => self.stdout.extend_from_slice(kept),
                }
                self.stdout_bytes = self.stdout_bytes.saturating_add(u64::try_from(take).unwrap_or(u64::MAX));
            }
            Some(STDERR) => append(&mut self.stderr, body, STDERR_BYTES),
            Some(STATUS) => append(&mut self.status, body, STATUS_BYTES),
            // A channel this client never asked for.
            _ => {}
        }
        if last {
            self.at_message_start = true;
            self.channel = None;
        }
        if self.stdout_bytes > self.ceiling {
            self.over_ceiling = true;
        }
        Ok(!self.over_ceiling)
    }

    pub fn over_ceiling(&self) -> bool {
        self.over_ceiling
    }

    /// What standard output held, when it was kept in memory; empty when it went to a sink.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Takes standard output out, for the result.
    pub fn take_stdout(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stdout)
    }

    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Flushes the sink, if any: what the command wrote is all on disk before it is read.
    pub fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.sink {
            Some(sink) => sink.flush(),
            None => Ok(()),
        }
    }

    /// The command's exit code, from the status channel — or `None` when the server sent no status, which means the
    /// command's end was never reported and nothing about it can be believed. An error when the status says the
    /// command did not run at all: a container that does not exist, a binary that is not in the image.
    pub fn exit_code(&self) -> Result<Option<i32>, KubernetesError> {
        if self.status.is_empty() {
            return Ok(None);
        }
        let Some(document) = json::read_tree(&self.status) else {
            return Err(KubernetesError::unanswered("The exec status was not a status document."));
        };
        let document = Some(&document);
        if json::text(json::path(document, "status")) == "Success" {
            return Ok(Some(0));
        }
        if json::text(json::path(document, "reason")) == "NonZeroExitCode" {
            for cause in json::children(json::path(json::path(document, "details"), "causes")) {
                if json::text(json::path(Some(cause), "reason")) == "ExitCode" {
                    match vectispire_domain::java::parse_int(&json::text(json::path(Some(cause), "message"))) {
                        Ok(code) => return Ok(Some(code)),
                        Err(_) => break,
                    }
                }
            }
        }
        let code = json::int(json::path(document, "code"));
        Err(KubernetesError::new(
            format!("The command did not run: {}", json::text_or(json::path(document, "message"), "no message")),
            u16::try_from(code).unwrap_or(0),
        ))
    }
}

fn append(into: &mut Vec<u8>, fragment: &[u8], limit: usize) {
    let room = limit.saturating_sub(into.len()).min(fragment.len());
    into.extend_from_slice(fragment.get(..room).unwrap_or_default());
}

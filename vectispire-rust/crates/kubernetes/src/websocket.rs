//! The WebSocket framing an `exec` needs (RFC 6455, client side) — what the JDK's `WebSocket` does for the Java
//! executor, written here rather than taken from a crate: the API server is the only peer, the subprotocol is one,
//! and what is read is bounded by [`crate::channels::ExecChannels`] before it is kept.
//!
//! The client masks every frame it sends, with a fresh random key; the server's frames are read unmasked (or unmasked,
//! should one arrive masked). A data frame's payload is handed over in chunks as it arrives, never held whole: a
//! frame's length is the server's to declare, and a large one is a report being streamed, not a reason to allocate it.
//! Control frames are small by the protocol's rule (125 bytes) and refused past it; a ping is answered.

use base64::Engine;
use rand_core::RngCore;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt};

/// The key a handshake's answer is computed from (RFC 6455 §1.3).
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// A data chunk handed over at a time.
const CHUNK: u64 = 64 * 1024;
/// A control frame's payload, at most.
const CONTROL_BYTES: u64 = 125;

pub const CONTINUATION: u8 = 0x0;
pub const TEXT: u8 = 0x1;
pub const BINARY: u8 = 0x2;
pub const CLOSE: u8 = 0x8;
pub const PING: u8 = 0x9;
pub const PONG: u8 = 0xA;

/// A fresh `Sec-WebSocket-Key`: sixteen random bytes, in base64.
pub fn key() -> String {
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The `Sec-WebSocket-Accept` a server answering `key` sends back.
pub fn accept_for(key: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest.finalize())
}

/// One frame from the client, masked with a fresh key.
pub fn client_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut mask = [0u8; 4];
    rand_core::OsRng.fill_bytes(&mut mask);
    masked_frame(opcode, payload, mask)
}

/// One complete (`FIN`) frame, masked with `mask`.
pub fn masked_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len().saturating_add(14));
    frame.push(0x80 | (opcode & 0x0f));
    let length = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    if let Ok(short) = u8::try_from(length)
        && short < 126
    {
        frame.push(0x80 | short);
    } else if let Ok(medium) = u16::try_from(length) {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&medium.to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&length.to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().zip(mask.iter().cycle()).map(|(byte, key)| byte ^ key));
    frame
}

/// What the server sent, as the reader hands it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A piece of a data message: `binary` as the message's first frame said, `last` at the message's end.
    Data { binary: bool, chunk: Vec<u8>, last: bool },
    /// A ping, whose payload the pong returns.
    Ping(Vec<u8>),
    /// The server closed the socket.
    Close,
}

/// The server's frames, read from `input`.
#[derive(Debug)]
pub struct Reader<R> {
    input: R,
    /// What is left of the data frame being read.
    remaining: u64,
    fin: bool,
    mask: Option<[u8; 4]>,
    /// Where the mask stands in the frame being read.
    offset: usize,
    /// Whether the message being read is binary, as its first frame said.
    binary: bool,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(input: R) -> Reader<R> {
        Reader { input, remaining: 0, fin: true, mask: None, offset: 0, binary: false }
    }

    /// The next event, or `None` when the stream ended.
    pub async fn next(&mut self) -> std::io::Result<Option<Event>> {
        loop {
            if self.remaining > 0 {
                let take = usize::try_from(self.remaining.min(CHUNK)).unwrap_or(0);
                let mut chunk = vec![0u8; take];
                self.input.read_exact(&mut chunk).await?;
                self.unmask(&mut chunk);
                self.remaining = self.remaining.saturating_sub(u64::try_from(take).unwrap_or(0));
                return Ok(Some(Event::Data { binary: self.binary, chunk, last: self.fin && self.remaining == 0 }));
            }
            let mut head = [0u8; 2];
            match self.input.read_exact(&mut head).await {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(error) => return Err(error),
            }
            let [first, second] = head;
            let fin = first & 0x80 != 0;
            let opcode = first & 0x0f;
            let masked = second & 0x80 != 0;
            let length = match second & 0x7f {
                126 => {
                    let mut extended = [0u8; 2];
                    self.input.read_exact(&mut extended).await?;
                    u64::from(u16::from_be_bytes(extended))
                }
                127 => {
                    let mut extended = [0u8; 8];
                    self.input.read_exact(&mut extended).await?;
                    u64::from_be_bytes(extended)
                }
                short => u64::from(short),
            };
            let mask = if masked {
                let mut key = [0u8; 4];
                self.input.read_exact(&mut key).await?;
                Some(key)
            } else {
                None
            };
            self.mask = mask;
            self.offset = 0;
            if opcode >= CLOSE {
                if !fin || length > CONTROL_BYTES {
                    return Err(protocol("a control frame longer than the protocol allows"));
                }
                let mut payload = vec![0u8; usize::try_from(length).unwrap_or(0)];
                self.input.read_exact(&mut payload).await?;
                self.unmask(&mut payload);
                match opcode {
                    CLOSE => return Ok(Some(Event::Close)),
                    PING => return Ok(Some(Event::Ping(payload))),
                    PONG => continue,
                    _ => return Err(protocol("a control frame of an unknown kind")),
                }
            }
            match opcode {
                TEXT => self.binary = false,
                BINARY => self.binary = true,
                CONTINUATION => {}
                _ => return Err(protocol("a data frame of an unknown kind")),
            }
            self.fin = fin;
            self.remaining = length;
            if length == 0 {
                return Ok(Some(Event::Data { binary: self.binary, chunk: Vec::new(), last: fin }));
            }
        }
    }

    fn unmask(&mut self, bytes: &mut [u8]) {
        let Some(mask) = self.mask else { return };
        for (byte, key) in bytes.iter_mut().zip(mask.iter().cycle().skip(self.offset)) {
            *byte ^= key;
        }
        self.offset = self.offset.saturating_add(bytes.len()).checked_rem(4).unwrap_or(0);
    }
}

fn protocol(what: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("The API server sent {what}."))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6455 §1.3's own example.
    #[test]
    fn the_handshake_answer_is_the_rfc_s() {
        assert_eq!(accept_for("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    /// RFC 6455 §5.7: a masked "Hello", and the three length forms.
    #[test]
    fn frames_are_masked_and_sized_as_the_rfc_writes_them() {
        assert_eq!(
            masked_frame(TEXT, b"Hello", [0x37, 0xfa, 0x21, 0x3d]),
            vec![0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]
        );
        assert_eq!(masked_frame(BINARY, &[0; 125], [0; 4]).get(1), Some(&(0x80 | 125)));
        assert_eq!(masked_frame(BINARY, &[0; 126], [0; 4]).get(1..4), Some(&[0x80 | 126, 0, 126][..]));
        let large = masked_frame(BINARY, &vec![0; 65_536], [0; 4]);
        assert_eq!(large.get(1..10), Some(&[0x80 | 127, 0, 0, 0, 0, 0, 1, 0, 0][..]));
        assert_ne!(
            client_frame(BINARY, b"x").get(2..6),
            client_frame(BINARY, b"x").get(2..6),
            "a fresh mask each time"
        );
    }

    #[tokio::test]
    async fn the_server_s_frames_are_read_in_chunks_by_message() {
        let mut stream = Vec::new();
        // A binary message in two frames, a ping, a masked text frame, an empty binary frame, then a close.
        stream.extend_from_slice(&[0x02, 3, 1, b'a', b'b']);
        stream.extend_from_slice(&[0x89, 2, b'h', b'i']);
        stream.extend_from_slice(&[0x80, 2, b'c', b'd']);
        stream.extend_from_slice(&[0x81, 0x82, 1, 2, 3, 4, b'o' ^ 1, b'k' ^ 2]);
        stream.extend_from_slice(&[0x82, 0]);
        stream.extend_from_slice(&[0x8A, 0, 0x88, 0]);
        let mut reader = Reader::new(&stream[..]);
        let mut events = Vec::new();
        while let Some(event) = reader.next().await.unwrap() {
            events.push(event);
        }
        assert_eq!(
            events,
            vec![
                Event::Data { binary: true, chunk: vec![1, b'a', b'b'], last: false },
                Event::Ping(b"hi".to_vec()),
                Event::Data { binary: true, chunk: b"cd".to_vec(), last: true },
                Event::Data { binary: false, chunk: b"ok".to_vec(), last: true },
                Event::Data { binary: true, chunk: Vec::new(), last: true },
                Event::Close,
            ]
        );
    }

    #[tokio::test]
    async fn a_large_frame_is_handed_over_in_chunks_and_a_long_control_frame_refused() {
        let mut stream = vec![0x82, 127, 0, 0, 0, 0, 0, 2, 0, 0];
        stream.extend(std::iter::repeat_n(7u8, 131_072));
        let mut reader = Reader::new(&stream[..]);
        let mut sizes = Vec::new();
        while let Some(Event::Data { chunk, last, .. }) = reader.next().await.unwrap() {
            sizes.push((chunk.len(), last));
        }
        assert_eq!(sizes, vec![(65_536, false), (65_536, true)]);

        let long_ping = [0x89, 126, 0, 126];
        assert!(Reader::new(&long_ping[..]).next().await.is_err());
        let unfinished_close = [0x08, 0];
        assert!(Reader::new(&unfinished_close[..]).next().await.is_err());
    }
}

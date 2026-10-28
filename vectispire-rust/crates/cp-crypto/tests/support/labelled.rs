//! The reference sets' randomness: `LabelledRandom` of `CryptoReferenceSetTest` and `EncryptionReferenceSetTest`.

use base64::Engine;
use sha2::{Digest, Sha256};

pub fn labelled(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

/// The 32 bytes of a label's digest in standard base64 — a key used as it is.
pub fn standard_key(label: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(labelled(label))
}

/// SHA-256(label ‖ ":" ‖ counter) blocks, the counter moving once per block and each call starting a fresh one —
/// exactly as Java's `nextBytes` fills. Only ever randomness for a test.
#[derive(Debug)]
pub struct LabelledRandom {
    label: String,
    counter: u64,
}

impl LabelledRandom {
    pub fn new(label: &str) -> LabelledRandom {
        LabelledRandom { label: label.to_owned(), counter: 0 }
    }

    pub fn boxed(label: &str) -> Box<dyn rand_core::RngCore + Send> {
        Box::new(LabelledRandom::new(label))
    }
}

impl rand_core::RngCore for LabelledRandom {
    fn next_u32(&mut self) -> u32 {
        unreachable!("the cipher draws bytes only")
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!("the cipher draws bytes only")
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(32) {
            let block = labelled(&format!("{}:{}", self.label, self.counter));
            self.counter += 1;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}

impl rand_core::CryptoRng for LabelledRandom {}

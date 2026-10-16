//! A value that must never reach a log line, an error message or a debug dump.

/// A secret in the clear — a deployment key, a token — whose `Debug` says only that it is one.
///
/// **Deliberately not `Display`**: the one way to read it is [`Secret::expose`], so every place that
/// handles the clear value names itself in the code.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Secret {
        Secret(value.into())
    }

    /// The clear value — for the one call that needs it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Secret(***)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Overwritten before the allocation is freed, so the clear value does not linger in a heap
        // page a core dump could show. Best effort: copies made by the libraries it was handed to are
        // theirs.
        let bytes = std::mem::take(&mut self.0).into_bytes();
        let mut bytes = bytes;
        bytes.iter_mut().for_each(|byte| *byte = 0);
        std::hint::black_box(&bytes);
    }
}

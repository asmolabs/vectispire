//! Why a scanner step produced nothing — `ScannerFailureException`.

use vectispire_container::RunnerError;

/// A scanner that did not give a usable result. Its step's artifact stays absent, never empty
/// (decision 0007): an empty list would say "analysed, nothing found" and resolve the backlog.
#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    /// The tool exited on a code that is not its "found something" one. Its own stderr is included,
    /// cut to 2,000 chars: without it the operator reads "the scanner failed" and has to guess.
    #[error("Scanner \"{label}\" exited with {code}. {stderr}")]
    Exited { label: String, code: i64, stderr: String },
    /// The container itself did not run to completion.
    #[error(transparent)]
    Runner(#[from] RunnerError),
}

impl ScannerError {
    pub fn exited(label: &str, code: i64, stderr: &str) -> ScannerError {
        let output = stderr.trim_matches(crate::jackson::is_java_whitespace);
        // `String.substring` counts UTF-16 units; so does this, without splitting a pair.
        let mut units = 0;
        let cut: String = output
            .chars()
            .take_while(|c| {
                units += c.len_utf16();
                units <= 2000
            })
            .collect();
        ScannerError::Exited { label: label.to_owned(), code, stderr: cut }
    }
}

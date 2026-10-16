//! The scanner images, pinned by multi-architecture index digest — `ScannerImages.PINNED`.
//!
//! **The same digests as the Java agent**, until the two are read from one source: a scanner version
//! that differs between two agents gives two backlogs for one target. The reference set compares the
//! create request, which names the image, so a drift here fails a test.

/// The secret scanner.
pub const GITLEAKS: &str =
    "zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f";

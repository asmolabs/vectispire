//! The scanner images, pinned by multi-architecture index digest — `ScannerImages.PINNED`.
//!
//! **The same digests as the Java agent**, until the two are read from one source: a scanner version
//! that differs between two agents gives two backlogs for one target. The reference set compares the
//! create request, which names the image, so a drift here fails a test.

/// The secret scanner.
pub const GITLEAKS: &str =
    "zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f";

/// The cataloguer, which takes the SBOM.
pub const SYFT: &str = "anchore/syft@sha256:1288ea4c8b38767b4e620c1e312c8cb26b6e887a99b4f07ab6cd19fc6f225026";

/// The vulnerability matcher, which also downloads and checks its own database.
pub const GRYPE: &str = "anchore/grype@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db";

/// The infrastructure checker.
pub const CHECKOV: &str = "bridgecrew/checkov@sha256:12a62da01af22654883aee3b9da18ba4297f123f5122663bf65235db37934144";

/// The source analyser.
pub const SEMGREP: &str = "semgrep/semgrep@sha256:bdf7013b2c3634a487671158da77c554f531742326b543a9464d2adf6c433ac8";

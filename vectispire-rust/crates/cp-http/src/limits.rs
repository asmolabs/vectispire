//! Request body ceilings per route class (`RequestBodyLimitFilter`), and the body that enforces them.
//!
//! **Two checks, because a declared length can lie by omission.** A `Content-Length` over the ceiling is refused
//! before anything reads a byte, as the chain's own 413 (title first, `;charset=UTF-8`). A body with no declared
//! length — chunked — is counted as it is read, and the read fails with [`BodyTooLarge`]; the extractor that was
//! reading turns that into the handler-shaped 413. One refusal, two shapes, depending on which check caught it:
//! exactly as the Java control plane answers, and pinned by `login-too-large-declared` and `-chunked`.

use crate::routing::routed_path;
use axum::body::Body;
use bytes::Bytes;
use http_body::{Body as HttpBody, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};

/// The Java side's `vectispire.http.max-body.*`, one field per route class, with its shipped defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyLimits {
    pub ticket_webhook: u64,
    pub vex_ingest: u64,
    pub agent_result: u64,
    pub sign_in: u64,
    pub sarif_import: u64,
    pub coverage_import: u64,
    pub test_report_import: u64,
    pub sbom_import: u64,
    pub checklist_template_import: u64,
    pub checklist_evidence: u64,
    pub rule_set_upload: u64,
    pub fallback: u64,
}

const KB: u64 = 1024;
const MB: u64 = 1024 * 1024;

impl Default for BodyLimits {
    fn default() -> BodyLimits {
        BodyLimits {
            ticket_webhook: MB,
            vex_ingest: 16 * MB,
            // An agent's result carries the SBOM; decision 0038 sets the ingress to match.
            agent_result: 256 * MB,
            sign_in: 16 * KB,
            sarif_import: 32 * MB,
            coverage_import: 16 * MB,
            test_report_import: 32 * MB,
            sbom_import: 32 * MB,
            checklist_template_import: 10 * MB,
            checklist_evidence: 25 * MB,
            rule_set_upload: 64 * MB,
            fallback: MB,
        }
    }
}

impl BodyLimits {
    /// The ceiling for a request: its route class's, or the fallback. Only a POST has a class of its own.
    pub fn ceiling(&self, method: &str, raw_path: &str) -> u64 {
        if !method.eq_ignore_ascii_case("POST") {
            return self.fallback;
        }
        let path = routed_path(raw_path);
        let p = path.as_str();
        let under = |prefix: &str| p.starts_with(prefix);
        let ends = |suffix: &str| p.ends_with(suffix);
        if under("/api/v1/tickets/webhook/") {
            self.ticket_webhook
        } else if p == "/api/v1/vex/ingest" {
            self.vex_ingest
        } else if under("/api/v1/agent/jobs/") && ends("/result") {
            self.agent_result
        } else if under("/api/v1/repositories/") && ends("/sarif-imports") {
            self.sarif_import
        } else if under("/api/v1/repositories/") && ends("/coverage-imports") {
            self.coverage_import
        } else if under("/api/v1/repositories/") && ends("/test-report-imports") {
            self.test_report_import
        } else if under("/api/v1/repositories/") && ends("/build-sbom-imports") {
            self.sbom_import
        } else if is_template_import(p) {
            self.checklist_template_import
        } else if under("/api/v1/projects/") && p.contains("/checklists/") && ends("/evidence/files") {
            self.checklist_evidence
        } else if p == "/api/v1/rule-sets" {
            self.rule_set_upload
        } else if under("/api/v1/auth/") {
            self.sign_in
        } else {
            self.fallback
        }
    }
}

/// The import alone, `…/{slug}/versions`: a version's own routes (`…/versions/2/derive`) carry a few bytes of
/// JSON and take the default.
fn is_template_import(path: &str) -> bool {
    const PREFIX: &str = "/api/v1/checklist-templates/";
    path.strip_prefix(PREFIX)
        .and_then(|rest| rest.strip_suffix("/versions"))
        .is_some_and(|slug| !slug.is_empty() && !slug.contains('/'))
}

/// Spring's `DataSize.parse`: a number and an optional unit (`B`, `KB`, `MB`, `GB`, `TB`, any case), bytes by
/// default, powers of 1024.
pub fn parse_data_size(text: &str) -> Option<u64> {
    let text = text.trim();
    let digits_end = text.find(|c: char| !c.is_ascii_digit() && c != '-' && c != '+').unwrap_or(text.len());
    let (number, unit) = text.split_at(digits_end);
    let number: u64 = number.parse().ok()?;
    let factor = match unit.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "KB" => KB,
        "MB" => MB,
        "GB" => MB * KB,
        "TB" => MB * MB,
        _ => return None,
    };
    number.checked_mul(factor)
}

/// A body that has passed its route's ceiling while being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyTooLarge {
    pub ceiling: u64,
}

impl std::fmt::Display for BodyTooLarge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", too_large_detail(self.ceiling))
    }
}

impl std::error::Error for BodyTooLarge {}

/// The [`BodyTooLarge`] somewhere in an error's chain of causes, if a read failed because of one.
pub fn find_too_large(error: &(dyn std::error::Error + 'static)) -> Option<BodyTooLarge> {
    let mut source = Some(error);
    while let Some(current) = source {
        if let Some(too_large) = current.downcast_ref::<BodyTooLarge>() {
            return Some(*too_large);
        }
        source = current.source();
    }
    None
}

/// The sentence both 413s carry.
pub fn too_large_detail(ceiling: u64) -> String {
    format!("The request body is larger than the {ceiling} bytes this route accepts.")
}

/// A request body that fails with [`BodyTooLarge`] the moment more than `ceiling` bytes have come out of it.
#[derive(Debug)]
pub struct Counting {
    inner: Body,
    ceiling: u64,
    read: u64,
}

impl Counting {
    pub fn wrap(inner: Body, ceiling: u64) -> Body {
        Body::new(Counting { inner, ceiling, read: 0 })
    }
}

impl HttpBody for Counting {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.read = self.read.saturating_add(data.len() as u64);
                    if self.read > self.ceiling {
                        return Poll::Ready(Some(Err(Box::new(BodyTooLarge { ceiling: self.ceiling }))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(Box::new(error)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[test]
    fn a_post_takes_its_route_classs_ceiling_and_everything_else_the_fallback() {
        let limits = BodyLimits::default();
        assert_eq!(limits.ceiling("POST", "/api/v1/auth/login"), 16 * KB);
        assert_eq!(limits.ceiling("POST", "/api/v1/auth/mfa/verify"), 16 * KB);
        assert_eq!(limits.ceiling("POST", "/api/v1/agent/jobs/12/result"), 256 * MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/agent/jobs/12/heartbeat"), MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/tickets/webhook/abc"), MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/vex/ingest"), 16 * MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/repositories/3/sarif-imports"), 32 * MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/repositories/3/coverage-imports"), 16 * MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/repositories/3/test-report-imports"), 32 * MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/repositories/3/build-sbom-imports"), 32 * MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/rule-sets"), 64 * MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/projects/4/checklists/open/evidence/files"), 25 * MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/projects"), MB);
        // Only a POST has a class of its own.
        assert_eq!(limits.ceiling("PUT", "/api/v1/auth/login"), MB);
        assert_eq!(limits.ceiling("GET", "/api/v1/rule-sets"), MB);
    }

    #[test]
    fn the_template_import_is_the_versions_route_alone() {
        let limits = BodyLimits::default();
        assert_eq!(limits.ceiling("POST", "/api/v1/checklist-templates/secure-delivery/versions"), 10 * MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/checklist-templates/secure-delivery/versions/2/derive"), MB);
        assert_eq!(limits.ceiling("POST", "/api/v1/checklist-templates/a/b/versions"), MB);
    }

    #[test]
    fn the_class_is_read_from_the_routed_path_not_the_raw_one() {
        let limits = BodyLimits::default();
        // The segment parameters and an encoded letter do not hide a route from its limit.
        assert_eq!(limits.ceiling("POST", "/api/v1/auth;x=1/login"), 16 * KB);
        assert_eq!(limits.ceiling("POST", "/api/v1/auth/%6Cogin"), 16 * KB);
    }

    #[test]
    fn data_sizes_parse_as_spring_parses_them() {
        assert_eq!(parse_data_size("1MB"), Some(MB));
        assert_eq!(parse_data_size("16KB"), Some(16 * KB));
        assert_eq!(parse_data_size("256mb"), Some(256 * MB));
        assert_eq!(parse_data_size("2GB"), Some(2 * MB * KB));
        assert_eq!(parse_data_size("500"), Some(500));
        assert_eq!(parse_data_size("10 B"), Some(10));
        assert_eq!(parse_data_size("MB"), None);
        assert_eq!(parse_data_size("1XB"), None);
    }

    #[tokio::test]
    async fn a_body_past_its_ceiling_fails_while_it_is_read() {
        let body = Counting::wrap(Body::from(vec![0u8; 11]), 10);
        let error = body.collect().await.expect_err("past the ceiling");
        assert_eq!(find_too_large(&error).expect("the typed error").ceiling, 10);
    }

    #[tokio::test]
    async fn a_body_at_its_ceiling_is_read_whole() {
        let body = Counting::wrap(Body::from(vec![7u8; 10]), 10);
        assert_eq!(body.collect().await.expect("within").to_bytes().len(), 10);
    }

    #[test]
    fn the_sentence_names_the_ceiling() {
        assert_eq!(too_large_detail(16384), "The request body is larger than the 16384 bytes this route accepts.");
    }
}

//! Spring MVC's reflected-file-download guard — `AbstractMessageConverterMethodProcessor.addContentDispositionHeader`:
//! an answer written by a message converter to a path whose last segment carries an extension Spring does not hold
//! safe gets `Content-Disposition: inline;filename=f.txt`, so a browser cannot be led to save it as `x.bat`.
//!
//! A path naming a control (`/soa/ISO_27001/ISO-A.8.8`) has the "extension" `8`, and every answer of that route —
//! the 200 and the problems alike — carries the header in Java. What is reproduced: the status rule (not on 1xx and
//! 3xx), the last segment cut at its path parameters and percent-decoded, the extension lower-cased against Spring's
//! safe list, and the matched pattern ending in the extension. Not reproduced: the extension resolved to a media type
//! through `MediaTypeFactory` (an `audio/`, `image/`, `video/` or `+xml` type is safe there); the safe list covers the
//! extensions Vectispire's paths carry.

use axum::response::Response;
use http::{HeaderValue, header};

/// `WHITELISTED_EXTENSIONS`.
const SAFE_EXTENSIONS: [&str; 16] = [
    "txt",
    "text",
    "yml",
    "properties",
    "csv",
    "json",
    "xml",
    "atom",
    "rss",
    "png",
    "jpe",
    "jpeg",
    "jpg",
    "gif",
    "wbmp",
    "bmp",
];

/// The answer, with the header Spring adds when `raw_path` ends in an unsafe extension the route `pattern` does not
/// itself end with.
pub fn guard(raw_path: &str, pattern: &str, mut response: Response) -> Response {
    let status = response.status().as_u16();
    if status < 200 || (300..400).contains(&status) || response.headers().contains_key(header::CONTENT_DISPOSITION) {
        return response;
    }
    let last = raw_path.rsplit('/').next().unwrap_or("");
    let (filename, parameters) = last.split_once(';').map_or((last, ""), |(name, rest)| (name, rest));
    let unsafe_extension = |text: &str| {
        let decoded = percent_encoding::percent_decode_str(text).decode_utf8_lossy();
        extension(&decoded).is_some_and(|extension| !safe(&extension, pattern))
    };
    if unsafe_extension(filename) || unsafe_extension(parameters) {
        response.headers_mut().insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("inline;filename=f.txt"));
    }
    response
}

/// `StringUtils.getFilenameExtension`: after the last dot, unless a slash follows it; empty is no extension.
fn extension(filename: &str) -> Option<String> {
    let dot = filename.rfind('.')?;
    let after = filename.get(dot.checked_add(1)?..)?;
    (!after.is_empty() && !after.contains('/')).then(|| after.to_lowercase())
}

fn safe(extension: &str, pattern: &str) -> bool {
    SAFE_EXTENSIONS.contains(&extension) || pattern.ends_with(&format!(".{extension}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;

    fn guarded(path: &str, status: StatusCode) -> Option<String> {
        let mut response = Response::new(axum::body::Body::empty());
        *response.status_mut() = status;
        guard(path, "/api/v1/x/{id}", response)
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .map(|value| value.to_str().unwrap_or_default().to_owned())
    }

    #[test]
    fn an_unsafe_extension_is_answered_inline_as_text() {
        let inline = Some("inline;filename=f.txt".to_owned());
        assert_eq!(guarded("/api/v1/x/ISO-A.8.8", StatusCode::OK), inline);
        assert_eq!(guarded("/api/v1/x/ISO-A.8.8", StatusCode::NOT_FOUND), inline);
        assert_eq!(guarded("/api/v1/x/a;b=c.exe", StatusCode::OK), inline);
        assert_eq!(guarded("/api/v1/x/A.BAT", StatusCode::OK), inline);
    }

    #[test]
    fn a_safe_or_absent_extension_and_a_redirect_are_left_alone() {
        assert_eq!(guarded("/api/v1/x/ISO-A", StatusCode::OK), None);
        assert_eq!(guarded("/api/v1/x/report.CSV", StatusCode::OK), None);
        assert_eq!(guarded("/api/v1/x/trailing.", StatusCode::OK), None);
        assert_eq!(guarded("/api/v1/x/a.8", StatusCode::FOUND), None);
        assert_eq!(guarded("/api/v1/x/a.8", StatusCode::CONTINUE), None);
        let pattern = guard("/api/v1/x/export.pdf", "/api/v1/x/export.pdf", Response::new(axum::body::Body::empty()));
        assert!(!pattern.headers().contains_key(header::CONTENT_DISPOSITION));
    }
}

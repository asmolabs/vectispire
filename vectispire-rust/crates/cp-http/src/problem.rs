//! RFC 9457 problem documents, in the two shapes the Java control plane answers them in.
//!
//! **Two shapes, because there are two writers.** The security chain writes its refusals itself
//! (`ProblemResponses`): `{"title","status","detail","instance"}` in that order, `application/problem+json;charset=UTF-8`.
//! Everything a controller or `ApiExceptionHandler` raises goes through Spring's `ProblemDetail` and Jackson:
//! `{"detail","instance","status","title"}`, then the `type` when there is one, then the properties, and a bare
//! `application/problem+json`. A client reads `detail` either way; the byte-for-byte comparison with the
//! recorded answers (`tests/golden/java/`) is what keeps the two from being "harmonised" by somebody tidying up.
//!
//! Strings are written with Jackson's escaping (control characters as `\uXXXX`, upper-case hex), not
//! `serde_json`'s: a detail that quotes a header value would otherwise differ from the Java answer.

use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use serde_json::Value;

/// Which of the two Java writers a problem is rendered as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writer {
    /// The chain's own `ProblemResponses.write` — filters and the denied/entry-point handlers.
    Chain,
    /// `ProblemDetail` through Jackson — controllers, `ApiExceptionHandler`, the MVC layer.
    Handler,
}

/// `urn:vectispire:problem:` — what a problem's `type` starts with when its conflict names a cause.
pub const PROBLEM_TYPE: &str = "urn:vectispire:problem:";

/// A refusal, rendered as the problem document the Java control plane would have answered.
///
/// Boxed: a problem is the `Err` of every extractor and every handler that can refuse, and a hundred-odd bytes there
/// is paid by the success path too.
#[derive(Clone, Debug)]
pub struct Problem(Box<Data>);

#[derive(Clone, Debug)]
struct Data {
    status: StatusCode,
    detail: String,
    instance: Option<String>,
    problem_type: Option<String>,
    properties: Vec<(String, Value)>,
    headers: Vec<(&'static str, String)>,
    writer: Writer,
}

impl Problem {
    /// A problem the way a controller or the exception handler answers it.
    pub fn handler(status: StatusCode, detail: impl Into<String>) -> Problem {
        Problem::new(status, detail, Writer::Handler)
    }

    /// A problem the way the security chain writes it.
    pub fn chain(status: StatusCode, detail: impl Into<String>) -> Problem {
        Problem::new(status, detail, Writer::Chain)
    }

    fn new(status: StatusCode, detail: impl Into<String>, writer: Writer) -> Problem {
        Problem(Box::new(Data {
            status,
            detail: detail.into(),
            instance: None,
            problem_type: None,
            properties: Vec::new(),
            headers: Vec::new(),
            writer,
        }))
    }

    /// The request path the problem answers (`instance`), as the client sent it.
    pub fn at(mut self, instance: impl Into<String>) -> Problem {
        self.0.instance = Some(instance.into());
        self
    }

    /// `type`, as `urn:vectispire:problem:<cause>` — a route whose 409 has several causes names each.
    pub fn caused_by(mut self, cause: &str) -> Problem {
        self.0.problem_type = Some(format!("{PROBLEM_TYPE}{cause}"));
        self
    }

    /// A member beside the standard ones — `retryAfterSeconds`, `correlationId`, what a conflict names.
    pub fn with(mut self, name: &str, value: impl Into<Value>) -> Problem {
        self.0.properties.push((name.to_owned(), value.into()));
        self
    }

    /// A header on the answer — `Retry-After`, `Allow`.
    pub fn header(mut self, name: &'static str, value: impl Into<String>) -> Problem {
        self.0.headers.push((name, value.into()));
        self
    }

    pub fn status(&self) -> StatusCode {
        self.0.status
    }

    pub fn detail(&self) -> &str {
        &self.0.detail
    }

    pub fn instance(&self) -> Option<&str> {
        self.0.instance.as_deref()
    }

    /// The status's phrase as Spring's `HttpStatus` spells it — which is not always `http`'s.
    pub fn title(status: StatusCode) -> &'static str {
        match status.as_u16() {
            413 => "Content Too Large",
            422 => "Unprocessable Content",
            _ => status.canonical_reason().unwrap_or("Error"),
        }
    }

    /// The document, as the Java side serialises it.
    pub fn body(&self) -> String {
        let title = Problem::title(self.0.status);
        let mut out = String::from("{");
        let member = |out: &mut String, name: &str, value: &Value| {
            if out.len() > 1 {
                out.push(',');
            }
            write_string(out, name);
            out.push(':');
            write_value(out, value);
        };
        let status = Value::from(self.0.status.as_u16());
        let detail = Value::from(self.0.detail.as_str());
        let title = Value::from(title);
        let instance = self.0.instance.as_deref().map(Value::from);
        match self.0.writer {
            Writer::Chain => {
                member(&mut out, "title", &title);
                member(&mut out, "status", &status);
                member(&mut out, "detail", &detail);
                if let Some(instance) = &instance {
                    member(&mut out, "instance", instance);
                }
            }
            Writer::Handler => {
                member(&mut out, "detail", &detail);
                if let Some(instance) = &instance {
                    member(&mut out, "instance", instance);
                }
                member(&mut out, "status", &status);
                member(&mut out, "title", &title);
                if let Some(kind) = &self.0.problem_type {
                    member(&mut out, "type", &Value::from(kind.as_str()));
                }
            }
        }
        for (name, value) in &self.0.properties {
            member(&mut out, name, value);
        }
        out.push('}');
        out
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let content_type = match self.0.writer {
            Writer::Chain => "application/problem+json;charset=UTF-8",
            Writer::Handler => "application/problem+json",
        };
        let mut response = Response::new(axum::body::Body::from(self.body()));
        // Kept on the response so that the layer that knows the request can fill in `instance`, as Spring does
        // from the request: a handler raising a refusal has no business knowing the path it was reached by.
        response.extensions_mut().insert(self.clone());
        *response.status_mut() = self.0.status;
        response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        for (name, value) in &self.0.headers {
            if let Ok(value) = HeaderValue::from_str(value) {
                response.headers_mut().append(*name, value);
            }
        }
        response
    }
}

/// A JSON string the way Jackson's default writer spells it: `"` and `\` escaped, the short escapes for the
/// five control characters that have one, `\u00XX` with **upper-case** hex for the rest below 0x20, everything
/// else — non-ASCII included — as it is.
pub fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(members) => {
            out.push('{');
            for (index, (name, member)) in members.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, name);
                out.push(':');
                write_value(out, member);
            }
            out.push('}');
        }
        other => out.push_str(&other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chain_writes_title_first_and_the_handler_detail_first() {
        let chain = Problem::chain(StatusCode::UNAUTHORIZED, "sign in").at("/x").body();
        assert_eq!(chain, r#"{"title":"Unauthorized","status":401,"detail":"sign in","instance":"/x"}"#);
        let handler = Problem::handler(StatusCode::NOT_FOUND, "gone").at("/x").body();
        assert_eq!(handler, r#"{"detail":"gone","instance":"/x","status":404,"title":"Not Found"}"#);
    }

    #[test]
    fn a_type_comes_after_the_title_and_the_members_after_it() {
        let body = Problem::handler(StatusCode::CONFLICT, "twice")
            .at("/x")
            .caused_by("target-already-registered")
            .with("existingRepositoryId", 1)
            .body();
        assert_eq!(
            body,
            r#"{"detail":"twice","instance":"/x","status":409,"title":"Conflict","type":"urn:vectispire:problem:target-already-registered","existingRepositoryId":1}"#
        );
    }

    #[test]
    fn a_chain_problem_carries_its_members_after_the_instance() {
        let body =
            Problem::chain(StatusCode::TOO_MANY_REQUESTS, "slow down").at("/x").with("retryAfterSeconds", 2).body();
        assert!(body.ends_with(r#""instance":"/x","retryAfterSeconds":2}"#), "{body}");
    }

    #[test]
    fn strings_are_escaped_as_jackson_escapes_them() {
        let mut out = String::new();
        write_string(&mut out, "a\"b\\c\n\u{1f}\u{7f}é");
        assert_eq!(out, "\"a\\\"b\\\\c\\n\\u001F\u{7f}é\"");
    }

    #[test]
    fn the_titles_are_springs() {
        assert_eq!(Problem::title(StatusCode::PAYLOAD_TOO_LARGE), "Content Too Large");
        assert_eq!(Problem::title(StatusCode::TOO_MANY_REQUESTS), "Too Many Requests");
        assert_eq!(Problem::title(StatusCode::UNSUPPORTED_MEDIA_TYPE), "Unsupported Media Type");
    }

    #[test]
    fn the_media_type_follows_the_writer() {
        let chain = Problem::chain(StatusCode::FORBIDDEN, "no").into_response();
        assert_eq!(chain.headers()[header::CONTENT_TYPE], "application/problem+json;charset=UTF-8");
        let handler = Problem::handler(StatusCode::FORBIDDEN, "no").into_response();
        assert_eq!(handler.headers()[header::CONTENT_TYPE], "application/problem+json");
    }
}

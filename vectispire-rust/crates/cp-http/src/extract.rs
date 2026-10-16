//! What a handler reads from a request, and refuses in the Java control plane's words.
//!
//! **`JsonBody` instead of `axum::Json`.** axum's rejections are plain text in axum's words; the Java side answers
//! a problem document whose `detail` the interface shows to the person (the defect `ApiExceptionHandler` exists to end:
//! a generic fallback where a sentence was owed). The three refusals are measured, not guessed — see the goldens
//! `login-bad-json`, `login-unsupported-media` and `login-too-large-chunked`.

use crate::limits::{find_too_large, too_large_detail};
use crate::principal::Principal;
use crate::problem::Problem;
use axum::body::Body;
use axum::extract::{FromRequest, FromRequestParts, OptionalFromRequestParts, Request};
use http::StatusCode;
use http::header::CONTENT_TYPE;
use http::request::Parts;
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;

/// A value whose deserialisation fails with this prefix was refused by the type itself — a record's constructor
/// refusing a value (`InvalidInputException`) — and keeps its sentence. Anything else is "not the shape this route
/// expects": the parser's own message quotes a position and a Rust type, which a client cannot act on.
pub const INPUT_REFUSED_PREFIX: &str = "input refused: ";

const UNREADABLE: &str = "The request body could not be read: it is not JSON, or not the shape this route expects.";

/// The principal the chain resolved; refuses 401 (as the chain's entry point does) when there is none.
#[derive(Clone, Debug)]
pub struct Caller(pub Principal);

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Caller, Problem> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(Caller)
            .ok_or_else(|| crate::chain::unauthenticated(parts.uri.path()))
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for Caller {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Option<Caller>, Self::Rejection> {
        Ok(parts.extensions.get::<Principal>().cloned().map(Caller))
    }
}

/// The client's address as the chain resolved it (`TrustedProxies`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientAddress(pub String);

impl<S: Send + Sync> FromRequestParts<S> for ClientAddress {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<ClientAddress, Self::Rejection> {
        Ok(parts.extensions.get::<ClientAddress>().cloned().unwrap_or_else(|| ClientAddress("unknown".to_owned())))
    }
}

/// The visibility a scoped route resolved for its caller — inserted by the route's gate, read by the handler.
#[derive(Clone, Debug)]
pub struct Scoped<V>(pub V);

impl<S: Send + Sync, V: Clone + Send + Sync + 'static> FromRequestParts<S> for Scoped<V> {
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Scoped<V>, Problem> {
        // Reached only by a handler on a route that did not declare `.scoped()`: a wiring defect, and a 500
        // that says so rather than a handler quietly running with no visibility.
        parts.extensions.get::<Scoped<V>>().cloned().ok_or_else(|| {
            Problem::handler(
                StatusCode::INTERNAL_SERVER_ERROR,
                "This route was registered without resolving a visibility.",
            )
        })
    }
}

/// A JSON request body, read under the route's ceiling and refused in the Java sentences.
#[derive(Clone, Debug)]
pub struct JsonBody<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for JsonBody<T> {
    type Rejection = Problem;

    async fn from_request(request: Request, _state: &S) -> Result<JsonBody<T>, Problem> {
        let (parts, body) = request.into_parts();
        if !is_json(&parts) {
            return Err(unsupported(&parts));
        }
        let bytes = read(body).await?;
        match serde_json::from_slice::<T>(&bytes) {
            Ok(value) => Ok(JsonBody(value)),
            Err(error) => {
                let message = error.to_string();
                let detail = message
                    .split_once(INPUT_REFUSED_PREFIX)
                    .map(|(_, refused)| refused.split(" at line ").next().unwrap_or("").to_owned())
                    .unwrap_or_else(|| UNREADABLE.to_owned());
                Err(Problem::handler(StatusCode::BAD_REQUEST, detail))
            }
        }
    }
}

/// The whole body, or the 413 / 400 the Java side answers.
async fn read(body: Body) -> Result<bytes::Bytes, Problem> {
    match body.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) => match find_too_large(&error) {
            Some(too_large) => {
                Err(Problem::handler(StatusCode::PAYLOAD_TOO_LARGE, too_large_detail(too_large.ceiling)))
            }
            None => Err(Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE)),
        },
    }
}

fn is_json(parts: &Parts) -> bool {
    let Some(content_type) = parts.headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let essence = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    essence == "application/json" || (essence.starts_with("application/") && essence.ends_with("+json"))
}

/// 415, quoting the content type as Spring does: with `;charset=UTF-8` appended when the client named no charset,
/// because the container forces the request encoding before the message converters read the header.
fn unsupported(parts: &Parts) -> Problem {
    let sent = parts.headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok());
    let quoted = match sent {
        None => "application/octet-stream".to_owned(),
        Some(value) if value.to_ascii_lowercase().contains("charset=") => value.to_owned(),
        Some(value) => format!("{};charset=UTF-8", value.trim()),
    };
    Problem::handler(StatusCode::UNSUPPORTED_MEDIA_TYPE, format!("Content-Type '{quoted}' is not supported."))
        // Spring lists what the route's converters read — here JSON and YAML — in `Accept`, as RFC 9110 asks of a 415.
        .header("Accept", "application/json, application/yaml, application/*+json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Login {
        username: String,
    }

    async fn body_of(content_type: Option<&str>, body: &'static str) -> Result<JsonBody<Login>, Problem> {
        let mut request = Request::builder().method("POST").uri("/x");
        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        JsonBody::<Login>::from_request(request.body(Body::from(body)).expect("a request"), &()).await
    }

    #[tokio::test]
    async fn a_json_body_is_read() {
        let read = body_of(Some("application/json"), r#"{"username":"a"}"#).await.expect("a login");
        assert_eq!(read.0.username, "a");
        assert!(body_of(Some("application/problem+json; charset=utf-8"), r#"{"username":"a"}"#).await.is_ok());
    }

    #[tokio::test]
    async fn text_that_is_not_json_is_a_400_with_the_sentence_the_interface_shows() {
        let refused = body_of(Some("application/json"), "{not json").await.expect_err("refused");
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(refused.detail(), UNREADABLE);
        let wrong_shape = body_of(Some("application/json"), "[]").await.expect_err("refused");
        assert_eq!(wrong_shape.detail(), UNREADABLE);
    }

    #[tokio::test]
    async fn another_media_type_is_a_415_quoting_it_as_spring_does() {
        let refused = body_of(Some("text/plain"), "x").await.expect_err("refused");
        assert_eq!(refused.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(refused.detail(), "Content-Type 'text/plain;charset=UTF-8' is not supported.");
        assert_eq!(
            body_of(Some("text/plain;charset=ISO-8859-1"), "x").await.expect_err("refused").detail(),
            "Content-Type 'text/plain;charset=ISO-8859-1' is not supported."
        );
        assert_eq!(
            body_of(None, "x").await.expect_err("refused").detail(),
            "Content-Type 'application/octet-stream' is not supported."
        );
    }

    #[tokio::test]
    async fn a_value_the_type_itself_refused_keeps_its_sentence() {
        #[derive(Debug)]
        struct Strict;
        impl<'de> Deserialize<'de> for Strict {
            fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Strict, D::Error> {
                Err(serde::de::Error::custom(format!("{INPUT_REFUSED_PREFIX}The name may not be blank.")))
            }
        }
        let request =
            Request::builder().header(CONTENT_TYPE, "application/json").body(Body::from("{}")).expect("a request");
        let refused = JsonBody::<Strict>::from_request(request, &()).await.expect_err("refused");
        assert_eq!(refused.detail(), "The name may not be blank.");
    }

    #[tokio::test]
    async fn a_body_that_outgrows_its_ceiling_is_a_413_in_the_handlers_shape() {
        let counted = crate::limits::Counting::wrap(Body::from(vec![b' '; 40]), 16);
        let request = Request::builder().header(CONTENT_TYPE, "application/json").body(counted).expect("a request");
        let refused = JsonBody::<Login>::from_request(request, &()).await.expect_err("refused");
        assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(refused.detail(), "The request body is larger than the 16 bytes this route accepts.");
    }
}

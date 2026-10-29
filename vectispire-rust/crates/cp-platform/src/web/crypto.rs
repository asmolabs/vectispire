//! The signing key's public half, signature verification, and the commands that check an export — `CryptoController`:
//!
//! - `GET /api/v1/crypto/public-key.pub` (`getPublicKey`): anonymous — publishing the key is the point;
//! - `POST /api/v1/crypto/verify` (`verifySignature`): any account — the answer names the key it checked against, and
//!   says whether that key is Vectispire's;
//! - `GET /api/v1/crypto/cosign-cli-helper` (`getCosignCliHelper`): any account — the key's id and the commands.

use std::sync::Arc;

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;
use serde_json::Value;
use vectispire_cp_crypto::{KeyStore, SigningError, SigningKeys};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::extract::UNREADABLE;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{JsonBody, Problem};

use super::{bad_request, ok, unexpected};

pub(super) const PUBLIC_KEY: &str = "/api/v1/crypto/public-key.pub";
pub(super) const VERIFY: &str = "/api/v1/crypto/verify";
pub(super) const COSIGN_HELPER: &str = "/api/v1/crypto/cosign-cli-helper";

/// `CosignSigner.ALGORITHM`.
const ALGORITHM: &str = "SHA256withECDSA";

/// `VerifyResponse`: `keyId` is `null` when nothing was checked.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct VerifyResponse {
    valid: bool,
    key_id: Option<String>,
    vectispire_key: bool,
    algorithm: &'static str,
    message: String,
}

impl VerifyResponse {
    /// The controller's own answer to a request without a payload or a signature: a 200 that says so, not a refusal.
    fn incomplete() -> VerifyResponse {
        VerifyResponse {
            valid: false,
            key_id: None,
            vectispire_key: false,
            algorithm: ALGORITHM,
            message: "Payload and signature are required.".to_owned(),
        }
    }
}

/// `VerifyRequest`, three `String` components bound as Jackson binds a record: absent or `null` is `null`, a number or
/// a boolean is its text, an array or an object refuses the body. A `null` body is a request of `null` — answered as one
/// missing both members.
#[derive(Debug, Default, PartialEq, Eq)]
struct VerifyRequest {
    payload: Option<String>,
    signature: Option<String>,
    public_key: Option<String>,
}

impl VerifyRequest {
    fn read(body: Value) -> Result<VerifyRequest, Problem> {
        let fields = match body {
            Value::Null => return Ok(VerifyRequest::default()),
            Value::Object(fields) => fields,
            _ => return Err(Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE)),
        };
        let text = |name: &str| match fields.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => Ok(Some(text.clone())),
            Some(Value::Number(number)) => Ok(Some(number.to_string())),
            Some(Value::Bool(flag)) => Ok(Some(flag.to_string())),
            Some(_) => Err(Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE)),
        };
        Ok(VerifyRequest { payload: text("payload")?, signature: text("signature")?, public_key: text("publicKey")? })
    }
}

/// `ApiExceptionHandler` on what `SigningKeyService` throws: a key the reviewer pasted is theirs to correct (400), a
/// deployment without `ENCRYPTION_KEY` is misconfigured (412), and the rest — a stored key nothing decrypts among them —
/// is the referenced 500, never the failure's own text.
fn refuse(method: &str, path: &str, error: SigningError) -> Response {
    match error {
        SigningError::InvalidPublicKey => bad_request(SigningError::InvalidPublicKey.to_string()),
        SigningError::MissingKey => {
            Problem::handler(StatusCode::PRECONDITION_FAILED, SigningError::MissingKey.to_string()).into_response()
        }
        failure => unexpected(method, path, &failure),
    }
}

/// The cosign commands, by name. `--insecure-ignore-tlog=true` on every cosign command: Vectispire signs with its own
/// key and uploads nothing to Rekor, and cosign 2 looks the signature up in the transparency log by default — without
/// the flag each answered "signature not found in transparency log" for every export ever produced, and an auditor
/// following them concluded the document was not signed.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Commands {
    cosign_verify_manifest: &'static str,
    cosign_verify_vex: &'static str,
    cosign_verify_cyclone_dx: &'static str,
    openssl_verify: &'static str,
}

const COMMANDS: Commands = Commands {
    cosign_verify_manifest: "cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true \
                             --signature manifest.json.sig manifest.json",
    cosign_verify_vex: "cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true --signature \
                        05_openvex_advisory.json.sig 05_openvex_advisory.json",
    cosign_verify_cyclone_dx: "cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true \
                               --signature 08_cyclonedx_1_5_vex.json.sig 08_cyclonedx_1_5_vex.json",
    openssl_verify: "openssl dgst -sha256 -verify vectispire-signing-key.pub -signature <(base64 -d manifest.json.sig) \
                     manifest.json",
};

/// The helper's answer — a `Map.of` on the Java side, whose order is salted per JVM run: the members are compared by
/// name, and written here in the order the source lists them.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CosignHelper {
    key_id: String,
    key_algorithm: &'static str,
    instructions: &'static str,
    commands: Commands,
}

/// The public key as a download: `application/x-pem-file`, named as every export's commands name it.
fn pem_download(pem: String) -> Response {
    let mut response = Response::new(Body::from(pem));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/x-pem-file;charset=UTF-8"));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"vectispire-signing-key.pub\""),
    );
    response
}

/// `getPublicKey`.
async fn public_key<S: KeyStore>(signing: &SigningKeys<S>) -> Response {
    match signing.public_key_pem().await {
        Ok(pem) => pem_download(pem),
        Err(failure) => refuse("GET", PUBLIC_KEY, failure),
    }
}

/// `verifySignature`: a request missing its payload or its signature is answered — `valid: false`, saying so — and
/// never checked against an empty one.
async fn verify<S: KeyStore>(signing: &SigningKeys<S>, body: Value) -> Response {
    let request = match VerifyRequest::read(body) {
        Ok(request) => request,
        Err(refused) => return refused.into_response(),
    };
    let (Some(payload), Some(signature)) = (request.payload, request.signature) else {
        return ok(&VerifyResponse::incomplete());
    };
    match signing.verify_with(payload.as_bytes(), &signature, request.public_key.as_deref()).await {
        Ok(result) => ok(&VerifyResponse {
            valid: result.valid,
            key_id: Some(result.key_id),
            vectispire_key: result.vectispire_key,
            algorithm: ALGORITHM,
            message: result.message,
        }),
        Err(failure) => refuse("POST", VERIFY, failure),
    }
}

/// `getCosignCliHelper`.
async fn cosign_helper<S: KeyStore>(signing: &SigningKeys<S>) -> Response {
    match signing.key_id().await {
        Ok(key_id) => ok(&CosignHelper {
            key_id,
            key_algorithm: "ECDSA_P256",
            instructions: "Verify artifacts using standard cosign or openssl CLI",
            commands: COMMANDS,
        }),
        Err(failure) => refuse("GET", COSIGN_HELPER, failure),
    }
}

pub(super) fn routes<S: KeyStore + 'static>(signing: Arc<SigningKeys<S>>, entries: &mut Vec<RouteEntry>) {
    let public = signing.clone();
    entries.push(Route::get(PUBLIC_KEY).requires(Access::Anonymous).names_no_target().handler(move || {
        let signing = public.clone();
        async move { public_key(&signing).await }
    }));

    let checking = signing.clone();
    entries.push(Route::post(VERIFY).requires(Access::Account).names_no_target().handler(
        move |JsonBody(body): JsonBody<Value>| {
            let signing = checking.clone();
            async move { verify(&signing, body).await }
        },
    ));

    entries.push(Route::get(COSIGN_HELPER).requires(Access::Account).names_no_target().handler(move || {
        let signing = signing.clone();
        async move { cosign_helper(&signing).await }
    }));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Mutex;

    use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
    use vectispire_cp_settings::SettingsError;

    use super::*;

    /// The internal row, in memory: each store generates and keeps a key of its own.
    #[derive(Debug, Default)]
    struct Memory(Mutex<Option<String>>);

    impl KeyStore for Memory {
        async fn internal_value(&self, _key: &str) -> Result<Option<String>, SettingsError> {
            Ok(self.0.lock().unwrap().clone())
        }
        async fn store_internal_if_absent(&self, _key: &str, value: &str) -> Result<bool, SettingsError> {
            let mut row = self.0.lock().unwrap();
            if row.is_some() {
                return Ok(false);
            }
            *row = Some(value.to_owned());
            Ok(true)
        }
    }

    fn encryption(key: Option<&str>) -> Arc<Encryption> {
        let config =
            EncryptionConfig { key: key.map(vectispire_domain::secret::Secret::new), ..EncryptionConfig::default() };
        let door = VaultDoor {
            sender: vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
            guard: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
        };
        Arc::new(Encryption::new(&config, door).unwrap())
    }

    /// A key generated on first use and kept under a test `ENCRYPTION_KEY`, as a deployment without a configured one.
    fn generated() -> SigningKeys<Memory> {
        let key = "cGxhdGZvcm0tcm91dGVzLXRlc3Qta2V5LTMyLWJ5dGU="; // gitleaks:allow — test fixture
        SigningKeys::new("", Memory::default(), encryption(Some(key))).unwrap()
    }

    async fn answer(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn a_request_missing_its_payload_or_its_signature_is_answered_and_nothing_is_checked() {
        let signing = generated();
        for body in [r#"{"payload":"x"}"#, r#"{"signature":"x"}"#, "null", "{}"] {
            let (status, json) = answer(verify(&signing, serde_json::from_str(body).unwrap()).await).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(json["valid"], false, "{body}");
            assert_eq!(json["keyId"], Value::Null, "{body}");
            assert_eq!(json["message"], "Payload and signature are required.", "{body}");
        }
    }

    #[tokio::test]
    async fn a_signature_is_checked_against_the_key_it_names_and_says_whose_it_is() {
        let ours = generated();
        let payload = r#"{"status": "passed", "scanId": 42}"#;
        let signature = ours.sign(payload.as_bytes()).await.unwrap();
        let our_id = ours.key_id().await.unwrap();

        let (status, json) =
            answer(verify(&ours, serde_json::json!({"payload": payload, "signature": signature})).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["valid"], true);
        assert_eq!(json["keyId"], our_id.as_str());
        assert_eq!(json["vectispireKey"], true);
        assert_eq!(json["algorithm"], "SHA256withECDSA");

        let tampered = payload.replace("passed", "failed");
        let (_, json) =
            answer(verify(&ours, serde_json::json!({"payload": tampered, "signature": signature})).await).await;
        assert_eq!(json["valid"], false);

        // A forgery under the forger's own key: valid for that key, and never called Vectispire's.
        let forger = generated();
        let forged = forger.sign(payload.as_bytes()).await.unwrap();
        let forger_pem = forger.public_key_pem().await.unwrap();
        let (_, json) = answer(
            verify(&ours, serde_json::json!({"payload": payload, "signature": forged, "publicKey": forger_pem})).await,
        )
        .await;
        assert_eq!(json["valid"], true);
        assert_eq!(json["vectispireKey"], false);
        assert_eq!(json["keyId"], forger.key_id().await.unwrap().as_str());
        assert!(json["message"].as_str().unwrap().contains("not Vectispire's"));

        let (status, json) = answer(
            verify(&ours, serde_json::json!({"payload": payload, "signature": forged, "publicKey": "not a key"})).await,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["detail"], "Invalid ECDSA public key format");
    }

    #[tokio::test]
    async fn the_published_key_and_the_helper_name_the_key_that_signs() {
        let signing = generated();
        let response = public_key(&signing).await;
        assert_eq!(response.status(), StatusCode::OK);
        let pem = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        assert_eq!(std::str::from_utf8(&pem).unwrap(), signing.public_key_pem().await.unwrap());
        let (status, json) = answer(cosign_helper(&signing).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["keyId"], signing.key_id().await.unwrap().as_str());
    }

    #[tokio::test]
    async fn without_an_encryption_key_nothing_is_generated_and_the_deployment_is_told_412() {
        let signing = SigningKeys::new("", Memory::default(), encryption(None)).unwrap();
        let (status, json) = answer(public_key(&signing).await).await;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(json["detail"], vectispire_cp_crypto::MISSING_KEY);
        let (status, _) = answer(cosign_helper(&signing).await).await;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    }

    fn read(json: &str) -> Result<VerifyRequest, String> {
        VerifyRequest::read(serde_json::from_str(json).unwrap()).map_err(|refused| refused.detail().to_owned())
    }

    #[test]
    fn a_request_is_bound_as_jackson_binds_the_record() {
        assert_eq!(read("null"), Ok(VerifyRequest::default()), "a null body is a null request");
        assert_eq!(read("{}"), Ok(VerifyRequest::default()));
        assert_eq!(
            read(r#"{"payload":42,"signature":true,"publicKey":null,"other":[1]}"#),
            Ok(VerifyRequest { payload: Some("42".into()), signature: Some("true".into()), public_key: None }),
            "a scalar is its text, an unknown member ignored"
        );
        assert_eq!(read(r#"{"payload":["x"]}"#), Err(UNREADABLE.to_owned()));
        assert_eq!(read(r#"{"signature":{}}"#), Err(UNREADABLE.to_owned()));
        assert_eq!(read("[]"), Err(UNREADABLE.to_owned()));
        assert_eq!(read(r#""x""#), Err(UNREADABLE.to_owned()));
    }

    #[test]
    fn a_request_without_payload_or_signature_is_answered_not_refused() {
        assert_eq!(
            vectispire_domain::wire::to_wire_string(&VerifyResponse::incomplete()),
            r#"{"valid":false,"keyId":null,"vectispireKey":false,"algorithm":"SHA256withECDSA","message":"Payload and signature are required."}"#
        );
    }

    #[test]
    fn every_cosign_command_skips_the_transparency_log_and_the_helper_names_the_key() {
        let helper = vectispire_domain::wire::to_wire_string(&CosignHelper {
            key_id: "ab12".to_owned(),
            key_algorithm: "ECDSA_P256",
            instructions: "Verify artifacts using standard cosign or openssl CLI",
            commands: COMMANDS,
        });
        let parsed: Value = serde_json::from_str(&helper).unwrap();
        assert_eq!(parsed["keyId"], "ab12");
        assert_eq!(parsed["keyAlgorithm"], "ECDSA_P256");
        for name in ["cosignVerifyManifest", "cosignVerifyVex", "cosignVerifyCycloneDx"] {
            let command = parsed["commands"][name].as_str().unwrap();
            assert!(command.starts_with("cosign verify-blob --key vectispire-signing-key.pub "), "{command}");
            assert!(command.contains(" --insecure-ignore-tlog=true "), "{command}");
        }
        assert_eq!(
            parsed["commands"]["cosignVerifyManifest"],
            "cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true --signature \
             manifest.json.sig manifest.json"
        );
        assert_eq!(
            parsed["commands"]["opensslVerify"],
            "openssl dgst -sha256 -verify vectispire-signing-key.pub -signature <(base64 -d manifest.json.sig) \
             manifest.json"
        );
    }

    #[test]
    fn a_pasted_key_is_400_a_missing_encryption_key_412_and_the_rest_a_referenced_500() {
        let status = |error| refuse("POST", VERIFY, error).status();
        assert_eq!(status(SigningError::InvalidPublicKey), StatusCode::BAD_REQUEST);
        assert_eq!(status(SigningError::MissingKey), StatusCode::PRECONDITION_FAILED);
        assert_eq!(status(SigningError::Unreadable), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status(SigningError::Vanished), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn the_public_key_is_a_named_pem_download() {
        let response = pem_download("-----BEGIN PUBLIC KEY-----\n".to_owned());
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/x-pem-file;charset=UTF-8");
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"vectispire-signing-key.pub\""
        );
    }
}

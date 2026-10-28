//! The client against a stub control plane on a loopback port — `AgentProtocolTest`, `AgentHttpTest`
//! and `AgentSealingKeyAnnouncementTest` of the Java agent, ported: what each route sends, and how each
//! answer is read.
//!
//! The sealed credentials are the Java side's own (`reference/crypto/java-vectors.json`): envelopes
//! `SealedEnvelope` sealed to the reference set's Rust key, so what is opened here is what the control
//! plane seals, not what this crate would seal for itself.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use vectispire_crypto::{ResultSigner, SealingKeyPair};
use vectispire_domain::FailureKind;
use vectispire_domain::failure::Classified;
use vectispire_domain::secret::Secret;
use vectispire_protocol::{
    AgentClient, AssignedTask, Description, FailureReported, Findings, PluginRef, ProtocolError, ScanArtifacts,
    SealingKeyOutcome, Target,
};
use vectispire_testkit::control_plane::{Response, StubControlPlane};
use vectispire_tls::TlsTrust;

const AGENT: &str = "3f2b6c1e-8d4a-4b7e-9c2f-5a1d0e7b9c34";

fn labelled(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn seed() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode([9u8; 32])
}

fn signer() -> ResultSigner {
    ResultSigner::from_base64_seed(&seed()).unwrap()
}

/// The reference set's Rust sealing key — the one the Java side sealed its envelopes to.
fn reference_sealing() -> SealingKeyPair {
    SealingKeyPair::from_secret_bytes(labelled("vectispire-rust-reference:rust-sealing-key"))
}

/// The Java side's envelope for `context`, and what it holds.
fn envelope(context: &str) -> (String, String) {
    let vectors = vectispire_testkit::read_json("crypto/java-vectors.json");
    let found = vectors["envelopes_to_rust"].as_array().unwrap().iter().find(|e| e["context"] == context).unwrap();
    (found["sealed"].as_str().unwrap().to_owned(), found["plain"].as_str().unwrap().to_owned())
}

fn client(stub: &StubControlPlane, signer: Option<ResultSigner>) -> AgentClient {
    AgentClient::new(
        stub.url(),
        Secret::new("invented-api-key"),
        &TlsTrust::BuiltIn,
        signer,
        reference_sealing(),
        1_760,
    )
    .unwrap()
}

fn description(client: &AgentClient, version: Option<&str>) -> Description {
    Description {
        contract_version: "1",
        hostname: "scanner-01".into(),
        platform: "linux aarch64".into(),
        scanner_engine: "docker".into(),
        sealing_public_key: client.sealing_public_key(),
        version: version.map(str::to_owned),
    }
}

fn hello_answer(mode: &str) -> Response {
    Response::json(
        200,
        json!({"id": AGENT, "name": "scanner-01", "contractVersion": "1", "maxConcurrent": 2, "credentialsMode": mode}),
    )
}

fn repository_task(private_key: Value, https: Value) -> Value {
    json!({"scanId": 12, "attempt": 3, "task": {
        "target": {"kind": "repository", "url": "https://gitlab.example.org/g/p.git", "branch": "main",
                   "subPath": "svc", "privateKey": private_key, "https": https},
        "rulesHash": "r1", "steps": ["SECRETS", "SAST"],
        "plugins": [{"id": "lic", "digest": "d1"}, {"id": "arm", "digest": "d2", "runsUnsigned": true}]}})
}

fn unusable(result: Result<vectispire_protocol::Claim, ProtocolError>) -> (AssignedTask, String) {
    match result {
        Err(error @ ProtocolError::UnusableTask { .. }) => {
            assert_eq!(error.failure_kind(), FailureKind::Permanent);
            let ProtocolError::UnusableTask { assigned, message } = error else { unreachable!() };
            (*assigned, message)
        }
        other => panic!("expected an unusable task, got {other:?}"),
    }
}

// ------------------------------------------------------------------------------------------- HTTP

#[tokio::test]
async fn every_request_carries_the_api_key_and_asks_for_json_and_only_a_body_has_a_content_type() {
    let stub = StubControlPlane::answering(vec![hello_answer("local"), Response::status(204)]);
    let client = client(&stub, None);
    client.hello(&description(&client, Some("0.12.0-dev"))).await.unwrap();
    client.claim(Duration::from_secs(1)).await.unwrap();
    let seen = stub.requests();
    assert_eq!(seen.len(), 2);
    for request in &seen {
        assert_eq!(request.header("authorization"), Some("Bearer invented-api-key"));
        assert_eq!(request.header("accept"), Some("application/json"));
    }
    assert_eq!(seen[0].header("content-type"), Some("application/json"));
    assert_eq!(seen[1].header("content-type"), None, "a claim has no body, so no content type");
    assert_eq!(seen[1].target, "/api/v1/agent/jobs?wait=1");
}

#[tokio::test]
async fn a_redirect_is_not_followed_because_the_next_host_is_one_nobody_declared() {
    let elsewhere = StubControlPlane::answering(vec![Response::status(204)]);
    let stub = StubControlPlane::answering(vec![
        Response::status(302).with_header("Location", format!("{}/api/v1/agent/jobs", elsewhere.url())),
    ]);
    let refused = client(&stub, None).claim(Duration::from_secs(1)).await;
    assert!(matches!(refused, Err(ProtocolError::Refused(_))), "{refused:?}");
    assert!(elsewhere.requests().is_empty(), "nothing reached the redirect's host");
}

#[tokio::test]
async fn an_answer_that_is_not_json_is_kept_as_its_first_500_characters() {
    let page = format!("<html>{}</html>", "x".repeat(2_000));
    let stub = StubControlPlane::answering(vec![Response::text(502, page.clone())]);
    let Err(ProtocolError::Refused(message)) = client(&stub, None).claim(Duration::from_secs(1)).await else {
        panic!("refused")
    };
    assert_eq!(message, page.chars().take(500).collect::<String>());
}

#[tokio::test]
async fn the_server_s_detail_is_preferred_then_its_message_then_the_caller_s_wording() {
    let stub = StubControlPlane::answering(vec![
        Response::json(500, json!({"detail": "the detail", "message": "the message"})),
        Response::json(500, json!({"message": "the message"})),
        Response::json(500, json!({"detail": ""})),
    ]);
    let client = client(&stub, None);
    let mut messages = Vec::new();
    for _ in 0..3 {
        messages.push(client.claim(Duration::from_secs(1)).await.unwrap_err().to_string());
    }
    assert_eq!(messages, ["the detail", "the message", "Claim refused (HTTP 500)."]);
}

#[tokio::test]
async fn an_unreachable_control_plane_is_said_to_be_one() {
    let stub = StubControlPlane::answering(vec![]);
    let url = stub.url().to_owned();
    drop(stub);
    std::thread::sleep(Duration::from_millis(50));
    let client =
        AgentClient::new(&url, Secret::new("k"), &TlsTrust::BuiltIn, None, SealingKeyPair::generate(), 1).unwrap();
    let refused = client.claim(Duration::from_secs(1)).await.unwrap_err();
    assert!(matches!(refused, ProtocolError::Unreachable(_)), "{refused:?}");
    assert!(refused.to_string().starts_with("The control plane is unreachable: "));
    assert!(!refused.to_string().contains("invented"), "no key in the message");
}

// ------------------------------------------------------------------------------------------ hello

#[tokio::test]
async fn hello_is_snake_case_and_a_missing_version_is_left_out() {
    let stub = StubControlPlane::answering(vec![hello_answer("local"), hello_answer("local")]);
    let client = client(&stub, None);
    let identity = client.hello(&description(&client, None)).await.unwrap();
    assert_eq!((identity.max_concurrent, identity.credentials_mode.as_deref()), (2, Some("local")));
    client.hello(&description(&client, Some("0.12.0-dev"))).await.unwrap();
    let (without, with) = (stub.requests()[0].json(), stub.requests()[1].json());
    assert_eq!(without["contract_version"], "1");
    assert_eq!(without["sealing_public_key"], client.sealing_public_key());
    assert!(without.get("version").is_none(), "absent, neither null nor \"1\": {without}");
    assert_eq!(with["version"], "0.12.0-dev");
}

#[tokio::test]
async fn a_contract_mismatch_and_a_refused_key_are_errors_of_their_own() {
    let stub = StubControlPlane::answering(vec![
        Response::json(409, json!({"detail": "Contract 2 required."})),
        Response::json(401, json!({"detail": "API key refused."})),
        Response::status(403),
    ]);
    let client = client(&stub, None);
    let mismatch = client.hello(&description(&client, None)).await.unwrap_err();
    assert!(matches!(&mismatch, ProtocolError::ContractMismatch(message) if message == "Contract 2 required."));
    assert!(mismatch.is_fatal());
    for _ in 0..2 {
        let refused = client.hello(&description(&client, None)).await.unwrap_err();
        assert!(matches!(&refused, ProtocolError::Unauthorized(_)) && refused.is_fatal(), "{refused:?}");
    }
}

// ------------------------------------------------------------------------------- the sealing key

#[tokio::test]
async fn the_announcement_is_the_key_its_generation_and_a_signature_over_this_agent_s_id() {
    let stub = StubControlPlane::answering(vec![hello_answer("delegated"), Response::status(204)]);
    let client = client(&stub, Some(signer()));
    client.hello(&description(&client, None)).await.unwrap();
    assert_eq!(client.announce_sealing_key().await.unwrap(), SealingKeyOutcome::Accepted);
    let announced = stub.requests()[1].json();
    assert_eq!(stub.requests()[1].route(), "POST /api/v1/agent/sealing-key");
    assert_eq!(announced["public_key"], client.sealing_public_key());
    assert!(announced["generation"].is_i64(), "a number, past 32 bits on a real clock");
    assert!(vectispire_crypto::verify_sealing_key(
        &signer().public_key(),
        AGENT.parse().unwrap(),
        announced["generation"].as_i64().unwrap(),
        announced["public_key"].as_str().unwrap(),
        announced["signature"].as_str().unwrap()
    ));
}

#[tokio::test]
async fn each_answer_to_the_announcement_is_its_own_outcome_and_none_an_error() {
    let cases = [
        (200, SealingKeyOutcome::Accepted),
        (204, SealingKeyOutcome::Accepted),
        (202, SealingKeyOutcome::Accepted),
        (404, SealingKeyOutcome::NotSupported),
        (412, SealingKeyOutcome::NotPinned),
        (403, SealingKeyOutcome::Refused),
        (409, SealingKeyOutcome::Stale),
    ];
    for (status, expected) in cases {
        let stub = StubControlPlane::answering(vec![hello_answer("delegated"), Response::status(status)]);
        let client = client(&stub, Some(signer()));
        client.hello(&description(&client, None)).await.unwrap();
        assert_eq!(client.announce_sealing_key().await.unwrap(), expected, "HTTP {status}");
    }
    let stub = StubControlPlane::answering(vec![hello_answer("delegated"), Response::status(401)]);
    let client = client(&stub, Some(signer()));
    client.hello(&description(&client, None)).await.unwrap();
    assert!(matches!(client.announce_sealing_key().await, Err(ProtocolError::Unauthorized(_))), "a refused key");
}

#[tokio::test]
async fn with_no_signing_key_or_before_the_hello_nothing_is_sent() {
    let stub = StubControlPlane::answering(vec![hello_answer("delegated")]);
    let unsigned = client(&stub, None);
    unsigned.hello(&description(&unsigned, None)).await.unwrap();
    assert_eq!(unsigned.announce_sealing_key().await.unwrap(), SealingKeyOutcome::Unsignable);
    let before_hello = client(&stub, Some(signer()));
    assert_eq!(before_hello.announce_sealing_key().await.unwrap(), SealingKeyOutcome::Unsignable);
    assert_eq!(stub.routes(), ["POST /api/v1/agent/hello"]);
}

#[tokio::test]
async fn a_withheld_credential_announces_again_after_an_acceptance_and_not_after_a_refusal() {
    let withheld = || Response::json(412, json!({"detail": "No verified sealing key for this agent."}));
    let stub = StubControlPlane::answering(vec![
        hello_answer("delegated"),
        Response::status(204),
        withheld(),
        Response::status(403),
        withheld(),
    ]);
    let client = client(&stub, Some(signer()));
    client.hello(&description(&client, None)).await.unwrap();
    client.announce_sealing_key().await.unwrap();
    let first = client.claim(Duration::from_secs(1)).await.unwrap_err();
    assert_eq!(first.to_string(), "No verified sealing key for this agent.");
    let second = client.claim(Duration::from_secs(1)).await.unwrap_err();
    assert!(matches!(second, ProtocolError::Refused(_)));
    assert_eq!(
        stub.routes(),
        [
            "POST /api/v1/agent/hello",
            "POST /api/v1/agent/sealing-key",
            "GET /api/v1/agent/jobs",
            "POST /api/v1/agent/sealing-key",
            "GET /api/v1/agent/jobs",
        ],
        "announced again once after the acceptance; quiet after the refusal"
    );
}

#[tokio::test]
async fn a_412_names_its_cause_instead_of_failing_the_clone_later() {
    let stub = StubControlPlane::answering(vec![Response::status(412)]);
    let refused = client(&stub, None).claim(Duration::from_secs(1)).await.unwrap_err();
    assert_eq!(
        refused.to_string(),
        "A delegated credential was withheld: the control plane holds no verified sealing key for this agent."
    );
}

// ----------------------------------------------------------------------------------------- claims

#[tokio::test]
async fn an_empty_queue_is_a_204_and_the_limit_travels_on_every_answer() {
    let stub = StubControlPlane::answering(vec![
        Response::status(204),
        Response::status(204).with_header("X-Vectispire-Max-Concurrent", "3"),
        Response::json(200, repository_task(Value::Null, Value::Null)).with_header("X-Vectispire-Max-Concurrent", "40"),
        Response::status(204).with_header("X-Vectispire-Max-Concurrent", "lots"),
    ]);
    let client = client(&stub, None);
    let none = client.claim(Duration::from_secs(1)).await.unwrap();
    assert!(none.task.is_none() && none.max_concurrent.is_none(), "absent stays absent");
    assert_eq!(client.claim(Duration::from_secs(1)).await.unwrap().max_concurrent, Some(3));
    let claimed = client.claim(Duration::from_secs(1)).await.unwrap();
    assert_eq!(claimed.max_concurrent, Some(16), "held to the maximum");
    let task = claimed.task.unwrap();
    assert_eq!((task.scan_id, task.attempt), (12, Some(3)));
    assert_eq!(client.claim(Duration::from_secs(1)).await.unwrap().max_concurrent, None);
}

#[tokio::test]
async fn a_sealed_deployment_key_is_opened_and_the_rest_of_the_task_kept() {
    let (sealed, plain) = envelope("deployment-key");
    let stub = StubControlPlane::answering(vec![Response::json(200, repository_task(json!(sealed), Value::Null))]);
    let task = client(&stub, None).claim(Duration::from_secs(1)).await.unwrap().task.unwrap();
    let Target::Repository(repository) = &task.task.target else { panic!("a repository") };
    assert_eq!(repository.private_key.as_ref().unwrap().expose(), plain);
    assert_eq!((repository.branch.as_deref(), repository.sub_path.as_deref()), (Some("main"), Some("svc")));
    assert_eq!(task.task.rules_hash.as_deref(), Some("r1"));
    assert_eq!(
        task.task.plugins,
        [
            PluginRef { id: "lic".into(), digest: "d1".into(), runs_unsigned: false },
            PluginRef { id: "arm".into(), digest: "d2".into(), runs_unsigned: true }
        ],
        "opening a credential keeps the plugins — the Java agent once lost them here"
    );
}

#[tokio::test]
async fn a_sealed_https_token_is_opened_under_the_host_and_user_it_arrived_with() {
    let (sealed, plain) = envelope("https-token:18:gitlab.example.org;14:x-access-token;");
    let https = json!({"host": "gitlab.example.org", "username": "x-access-token", "token": sealed});
    let stub = StubControlPlane::answering(vec![Response::json(200, repository_task(Value::Null, https))]);
    let task = client(&stub, None).claim(Duration::from_secs(1)).await.unwrap().task.unwrap();
    let Target::Repository(repository) = &task.task.target else { panic!("a repository") };
    let https = repository.https.as_ref().unwrap();
    assert_eq!(https.token.as_ref().unwrap().expose(), plain);
    assert_eq!(task.task.plugins.len(), 2);
    assert!(!format!("{task:?}").contains(&plain), "opened, and still out of a debug dump");
}

#[tokio::test]
async fn a_credential_that_cannot_be_used_fails_the_claim_by_name_and_names_the_scan_for_its_report() {
    let (key, _) = envelope("deployment-key");
    let (token, _) = envelope("https-token:18:gitlab.example.org;14:x-access-token;");
    let mut tampered = key.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    let cases = [
        (
            repository_task(json!(tampered), Value::Null),
            "The sealed deployment key could not be opened: it is not addressed to this process, or it or what it is \
             bound to was altered on the way.",
        ),
        (
            repository_task(json!("-----BEGIN OPENSSH PRIVATE KEY----- invented"), Value::Null),
            "A deployment key arrived unsealed although this agent announced a sealing key: the announcement was \
             removed on the way. Refusing it rather than using it.",
        ),
        (
            repository_task(json!("sealed:v1:AAAA"), Value::Null),
            "A deployment key arrived sealed in the format of a control plane older than this agent, which does not \
             bind it to its destination. Refusing it: update the control plane.",
        ),
        (
            // The host rewritten on the way: the envelope is bound to the one it was sealed for.
            repository_task(
                Value::Null,
                json!({"host": "attacker.example.net", "username": "x-access-token", "token": token}),
            ),
            "The sealed HTTPS token could not be opened: it is not addressed to this process, or it or what it is \
             bound to was altered on the way.",
        ),
        (
            // A deployment key's envelope moved into the token's field: never sent as a password.
            repository_task(
                Value::Null,
                json!({"host": "gitlab.example.org", "username": "x-access-token", "token": key}),
            ),
            "The sealed HTTPS token could not be opened: it is not addressed to this process, or it or what it is \
             bound to was altered on the way.",
        ),
        (
            repository_task(
                Value::Null,
                json!({"host": "gitlab.example.org", "username": null, "token": "invented-clear-token"}),
            ),
            "A HTTPS token arrived unsealed although this agent announced a sealing key: the announcement was \
             removed on the way. Refusing it rather than using it.",
        ),
    ];
    for (body, expected) in cases {
        let stub = StubControlPlane::answering(vec![Response::json(200, body)]);
        let (assigned, message) = unusable(client(&stub, None).claim(Duration::from_secs(1)).await);
        assert_eq!(message, expected);
        assert_eq!((assigned.scan_id, assigned.attempt), (12, Some(3)), "named for the report");
    }
}

#[tokio::test]
async fn an_image_task_and_a_public_repository_pass_as_they_came() {
    let image = json!({"scanId": 5, "attempt": 1, "task": {"target": {"kind": "image",
        "reference": {"registry": "docker.io", "imageName": "library/alpine", "tag": "3"}, "platform": "linux/amd64"},
        "rulesHash": null, "steps": ["DEPENDENCIES"]}});
    let stub = StubControlPlane::answering(vec![
        Response::json(200, image),
        Response::json(200, repository_task(Value::Null, Value::Null)),
    ]);
    let client = client(&stub, None);
    let image = client.claim(Duration::from_secs(1)).await.unwrap().task.unwrap();
    assert!(matches!(image.task.target, Target::Image(_)));
    let public = client.claim(Duration::from_secs(1)).await.unwrap().task.unwrap();
    let Target::Repository(repository) = &public.task.target else { panic!("a repository") };
    assert!(repository.private_key.is_none() && repository.https.is_none());
}

#[tokio::test]
async fn an_unreadable_claim_is_a_failed_claim_not_a_task() {
    let stub = StubControlPlane::answering(vec![Response::json(
        200,
        json!({"scanId": 1, "task": {"target": {"kind": "bucket"}}}),
    )]);
    let refused = client(&stub, None).claim(Duration::from_secs(1)).await.unwrap_err();
    assert!(refused.to_string().starts_with("Claim unreadable: "), "{refused}");
    assert!(!refused.is_fatal());
}

// -------------------------------------------------------------------------------- rules, plugins

#[tokio::test]
async fn a_rule_set_is_fetched_once_because_a_hash_names_a_content() {
    let stub = StubControlPlane::answering(vec![Response::json(
        200,
        json!({"contentHash": "abc", "files": [{"path": "rule-0001.yaml", "originalName": "mine.yaml", "content": "rules: []"}]}),
    )]);
    let client = client(&stub, None);
    for _ in 0..3 {
        let files = client.rule_set("abc").await.unwrap();
        assert_eq!((files[0].path.as_str(), files[0].content.as_str()), ("rule-0001.yaml", "rules: []"));
    }
    assert_eq!(stub.routes(), ["GET /api/v1/agent/rules/abc"]);
}

#[tokio::test]
async fn a_refused_rule_set_is_an_error_and_never_the_bundled_rules() {
    let stub = StubControlPlane::answering(vec![Response::status(404), Response::status(404)]);
    let client = client(&stub, None);
    assert_eq!(client.rule_set("gone").await.unwrap_err().to_string(), "Rule set gone refused (HTTP 404).");
    assert!(client.rule_set("gone").await.is_err(), "a refusal is not cached either");
    let stub = StubControlPlane::answering(vec![]);
    let _ = client_for_path(&stub).rule_set("../../users").await;
    assert_eq!(stub.requests()[0].target, "/api/v1/agent/rules/..%2F..%2Fusers", "no other route reached");
}

fn client_for_path(stub: &StubControlPlane) -> AgentClient {
    client(stub, None)
}

#[tokio::test]
async fn a_plugin_is_fetched_by_id_and_digest_and_kept_only_when_it_hashes_to_that_digest() {
    let manifest =
        json!({"id": "lic", "name": "Licences", "image": "registry.example.org/lic@sha256:00", "network": false});
    let stub = StubControlPlane::answering(vec![
        Response::json(200, manifest.clone()),
        Response::json(200, manifest.clone()),
        Response::json(200, manifest.clone()),
        Response::status(404),
    ]);
    let client = client(&stub, None);
    let good = PluginRef { id: "lic".into(), digest: "d1".into(), runs_unsigned: false };
    let wrong = PluginRef { id: "lic".into(), digest: "d9".into(), runs_unsigned: false };
    let digest_of = |_: &Value| Some("d1".to_owned());
    assert_eq!(client.plugin(&good, digest_of).await.unwrap(), manifest);
    assert_eq!(client.plugin(&good, digest_of).await.unwrap(), manifest, "cached");
    // An answer that does not hash to the digest asked for is handed over — the runner refuses it — and
    // asked for again next time.
    client.plugin(&wrong, digest_of).await.unwrap();
    client.plugin(&wrong, digest_of).await.unwrap();
    let unknown = PluginRef { id: "nope".into(), digest: "d1".into(), runs_unsigned: false };
    assert_eq!(client.plugin(&unknown, digest_of).await.unwrap_err().to_string(), "Plugin nope refused (HTTP 404).");
    assert_eq!(
        stub.routes(),
        [
            "GET /api/v1/agent/plugins/lic/d1",
            "GET /api/v1/agent/plugins/lic/d9",
            "GET /api/v1/agent/plugins/lic/d9",
            "GET /api/v1/agent/plugins/nope/d1",
        ]
    );
}

// --------------------------------------------------------------------------- heartbeats, results

#[tokio::test]
async fn a_heartbeat_s_409_means_the_lease_is_gone_not_that_the_call_failed() {
    let stub = StubControlPlane::answering(vec![Response::status(204), Response::status(409), Response::status(500)]);
    let client = client(&stub, None);
    assert!(client.heartbeat(7).await.unwrap());
    assert!(!client.heartbeat(7).await.unwrap());
    assert!(client.heartbeat(7).await.is_err());
    assert_eq!(stub.routes()[0], "POST /api/v1/agent/jobs/7/heartbeat");
}

#[tokio::test]
async fn a_result_is_signed_over_the_bytes_sent_and_its_answers_read_as_the_java_agent_reads_them() {
    let stub = StubControlPlane::answering(vec![
        Response::json(200, json!({"accepted": true})),
        Response::status(409),
        Response::json(403, json!({"detail": "Attestation refused."})),
        Response::status(403),
        Response::status(500),
    ]);
    let client = client(&stub, Some(signer()));
    let artifacts = ScanArtifacts {
        secrets: Some(Findings::of(&[json!({"rule": "r", "line": 1})]).unwrap()),
        duration: Duration::from_millis(1_500),
        ..ScanArtifacts::default()
    };
    assert!(client.submit(44, &artifacts).await.unwrap());
    assert!(!client.submit(44, &artifacts).await.unwrap(), "the lease was taken over");
    let refused = client.submit(44, &artifacts).await.unwrap_err();
    assert!(matches!(&refused, ProtocolError::Unauthorized(message) if message == "Attestation refused."));
    assert_eq!(
        client.submit(44, &artifacts).await.unwrap_err().to_string(),
        "The control plane refused this result's attestation. The key in vectispire.agent.signing-key does not match \
         the one pinned for this agent."
    );
    assert_eq!(client.submit(44, &artifacts).await.unwrap_err().to_string(), "Result refused (HTTP 500).");

    let sent = &stub.requests()[0];
    assert_eq!(sent.route(), "POST /api/v1/agent/jobs/44/result");
    assert_eq!(sent.text(), artifacts.to_body().unwrap(), "the body is the one serialization");
    let signature = sent.header("x-vectispire-agent-signature").unwrap();
    assert!(vectispire_crypto::verify_result(&signer().public_key(), 44, &sent.body, signature));
    assert!(!vectispire_crypto::verify_failure(&signer().public_key(), 44, &sent.body, signature));
    assert_eq!(sent.json()["duration"], "PT1.5S");
}

#[tokio::test]
async fn an_agent_with_no_signing_key_sends_no_signature() {
    let stub = StubControlPlane::answering(vec![Response::status(200)]);
    assert!(client(&stub, None).submit(1, &ScanArtifacts::default()).await.unwrap());
    assert!(stub.requests()[0].header("x-vectispire-agent-signature").is_none());
}

// ---------------------------------------------------------------------------------- failure report

#[tokio::test]
async fn a_failure_report_names_its_attempt_and_kind_is_signed_as_a_failure_and_says_what_became_of_the_scan() {
    let stub = StubControlPlane::answering(vec![
        Response::json(200, json!({"retried": true, "attempt": 3, "maxAttempts": 3, "permanent": false})),
        Response::json(200, json!({"retried": false, "attempt": 3, "maxAttempts": 3, "permanent": true})),
        Response::status(409),
        Response::status(404),
        Response::status(403),
        Response::status(401),
    ]);
    let client = client(&stub, Some(signer()));
    let task: AssignedTask = serde_json::from_value(repository_task(Value::Null, Value::Null)).unwrap();
    assert_eq!(client.report_failure(&task, "why", FailureKind::Transient).await.unwrap(), FailureReported::Retried);
    assert_eq!(client.report_failure(&task, "why", FailureKind::Permanent).await.unwrap(), FailureReported::Failed);
    assert_eq!(client.report_failure(&task, "why", FailureKind::Transient).await.unwrap(), FailureReported::NotYours);
    assert_eq!(
        client.report_failure(&task, "why", FailureKind::Transient).await.unwrap(),
        FailureReported::NotSupported
    );
    assert_eq!(
        client.report_failure(&task, "why", FailureKind::Transient).await.unwrap_err().to_string(),
        "The control plane refused this report's attestation. The key in vectispire.agent.signing-key does not match \
         the one pinned for this agent."
    );
    assert!(matches!(
        client.report_failure(&task, "why", FailureKind::Transient).await,
        Err(ProtocolError::Unauthorized(_))
    ));

    let sent = &stub.requests()[0];
    assert_eq!(sent.route(), "POST /api/v1/agent/jobs/12/failure");
    assert_eq!(sent.json(), json!({"attempt": 3, "reason": "why", "kind": "TRANSIENT"}));
    assert_eq!(stub.requests()[1].json()["kind"], "PERMANENT");
    let signature = sent.header("x-vectispire-agent-signature").unwrap();
    assert!(vectispire_crypto::verify_failure(&signer().public_key(), 12, &sent.body, signature));
    assert!(!vectispire_crypto::verify_result(&signer().public_key(), 12, &sent.body, signature));
}

#[tokio::test]
async fn a_claim_with_no_attempt_comes_from_a_control_plane_without_the_report() {
    let stub = StubControlPlane::answering(vec![]);
    let mut task: AssignedTask = serde_json::from_value(repository_task(Value::Null, Value::Null)).unwrap();
    task.attempt = None;
    assert_eq!(
        client(&stub, None).report_failure(&task, "why", FailureKind::Transient).await.unwrap(),
        FailureReported::NotSupported
    );
    assert!(stub.requests().is_empty(), "nothing sent");
}

#[tokio::test]
async fn concurrent_calls_each_get_their_own_answer() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let stub = StubControlPlane::start(move |request| {
        counted.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        let scan: i64 = request.path().split('/').nth(5).unwrap().parse().unwrap();
        if scan % 2 == 0 { Response::status(204) } else { Response::status(409) }
    });
    let client = Arc::new(client(&stub, None));
    let beats: Vec<_> = (0..8)
        .map(|scan| {
            let client = client.clone();
            tokio::spawn(async move { (scan, client.heartbeat(scan).await.unwrap()) })
        })
        .collect();
    for beat in beats {
        let (scan, alive) = beat.await.unwrap();
        assert_eq!(alive, scan % 2 == 0);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 8);
}

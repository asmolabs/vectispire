//! The control plane's bodies around the result — `reference/artifacts/server-wire.json`, written by
//! `AgentWireReferenceSetTest` with the application's own mappers: the claim, the hello's and the failure
//! report's answers written byte for byte as Spring MVC writes them; the hello, the sealing-key
//! announcement and the failure report read as Java reads them; the contract number compared and each
//! route's refusal worded as `AgentsController` words it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use std::collections::BTreeSet;
use uuid::Uuid;
use vectispire_domain::FailureKind;
use vectispire_domain::instant::Instant;
use vectispire_domain::secret::Secret;
use vectispire_protocol::server::{
    self, FailureAnswer, FailureReport, HelloAnswer, HelloRequest, RouteRefusal, SealingKeyRequest, refusals,
};
use vectispire_protocol::{
    AssignedTask, HttpsCredential, Image, ImageReference, PluginRef, Repository, ScanTask, Step, Target, Unreadable,
};

const SEALED: &str = "sealed-envelope-placeholder-AAAA";

fn reference() -> Value {
    vectispire_testkit::read_json("artifacts/server-wire.json")
}

fn text(value: &str) -> Option<String> {
    Some(value.to_owned())
}

fn repository(
    url: &str,
    branch: Option<&str>,
    sub_path: Option<&str>,
    key: Option<&str>,
    https: Option<HttpsCredential>,
) -> Target {
    Target::Repository(Repository {
        url: url.to_owned(),
        branch: branch.map(str::to_owned),
        sub_path: sub_path.map(str::to_owned),
        private_key: key.map(Secret::new),
        https,
    })
}

fn image(registry: Option<&str>, name: &str, tag: &str, platform: Option<&str>) -> Target {
    Target::Image(Image {
        reference: ImageReference {
            registry: registry.map(str::to_owned),
            image_name: name.to_owned(),
            tag: tag.to_owned(),
        },
        platform: platform.map(str::to_owned),
    })
}

fn task(
    scan_id: i64,
    attempt: i32,
    target: Target,
    rules: Option<&str>,
    steps: &[Step],
    plugins: Vec<PluginRef>,
) -> AssignedTask {
    AssignedTask {
        scan_id,
        attempt: Some(attempt),
        task: ScanTask {
            target,
            rules_hash: rules.map(str::to_owned),
            steps: steps.iter().copied().collect::<BTreeSet<_>>(),
            plugins,
        },
    }
}

fn plugin(id: &str, digest: &str, runs_unsigned: bool) -> PluginRef {
    PluginRef { id: id.to_owned(), digest: digest.to_owned(), runs_unsigned }
}

/// The tasks `AgentWireReferenceSetTest.claims` builds, by name.
fn claim(name: &str) -> AssignedTask {
    match name {
        "repository-sealed-key" => task(
            7,
            1,
            repository("git@github.com:org/repo.git", Some("main"), None, Some(SEALED), None),
            Some("ab12"),
            &[Step::Secrets],
            vec![],
        ),
        "repository-https-token-plugins-every-step" => task(
            42,
            3,
            repository(
                "https://gitlab.example/g/p.git",
                None,
                Some("services/api"),
                None,
                Some(HttpsCredential {
                    host: text("gitlab.example"),
                    username: text("oauth2"),
                    token: Some(Secret::new(SEALED)),
                }),
            ),
            None,
            &[Step::Dependencies, Step::Secrets, Step::Iac, Step::Sast],
            vec![plugin("a", &"1".repeat(64), false), plugin("b", &"2".repeat(64), true)],
        ),
        "repository-https-without-username" => task(
            8,
            2,
            repository(
                "https://h.example/p.git",
                Some("dev"),
                None,
                None,
                Some(HttpsCredential { host: text("h.example"), username: None, token: Some(Secret::new(SEALED)) }),
            ),
            None,
            &[Step::Sast, Step::Iac],
            vec![],
        ),
        "image-by-digest" => task(
            9,
            1,
            image(
                Some("registry.example:5000"),
                "team/app",
                &format!("sha256:{}", "ab".repeat(32)),
                Some("linux/arm64"),
            ),
            None,
            &[Step::Dependencies],
            vec![],
        ),
        "image-docker-hub-no-step" => task(10, 1, image(None, "library/alpine", "3.20", None), None, &[], vec![]),
        "image-blank-registry" => {
            task(11, 1, image(Some(""), "library/alpine", "latest", Some("linux/amd64")), None, &[], vec![])
        }
        "text-escaping" => task(
            12,
            1,
            repository(
                "https://h.example/\"q\"\\b\u{1}\u{1f}\u{7f}\u{2028}\u{e9}\u{1F600}/<>&'.git",
                Some("feat/\u{e9}t\u{e9}\t\n\r\u{8}\u{c}"),
                Some("a b/\u{0}"),
                None,
                None,
            ),
            Some("\u{e9}"),
            &[Step::Secrets],
            vec![plugin("\u{2603}", "</script>", false)],
        ),
        "largest-numbers" => {
            task(i64::MAX, i32::MAX, repository("https://h.example/p.git", None, None, None, None), None, &[], vec![])
        }
        other => panic!("no claim {other}"),
    }
}

#[test]
fn the_claim_is_written_as_spring_mvc_writes_it() {
    let reference = reference();
    let claims = reference["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 8);
    for case in claims {
        let name = case["name"].as_str().unwrap();
        assert_eq!(claim(name).to_body().unwrap(), case["body"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn the_claim_reads_back_as_the_agent_reads_it() {
    let body = claim("repository-https-token-plugins-every-step").to_body().unwrap();
    let read: AssignedTask = serde_json::from_str(&body).unwrap();
    assert_eq!(read.task.secrets().iter().map(|secret| secret.expose()).collect::<Vec<_>>(), [SEALED]);
    assert_eq!(read.task.steps.len(), 4);
}

#[test]
fn the_hello_s_answer_is_written_as_spring_mvc_writes_it() {
    let reference = reference();
    let id = Some(Uuid::parse_str("0f8fad5b-d9cb-469f-a165-70867728950e").unwrap());
    for case in reference["hello"].as_array().unwrap() {
        let answer = match case["name"].as_str().unwrap() {
            "local" => HelloAnswer::new(id, text("build-agent-01"), 1, text("local")),
            "delegated-escaped-name" => {
                HelloAnswer::new(id, text("Agent \"\u{3b2}\" \\ \u{2603} \u{7}"), 16, text("delegated"))
            }
            "nothing-known" => HelloAnswer::new(None, None, 0, None),
            other => panic!("no hello {other}"),
        };
        assert_eq!(answer.to_body().unwrap(), case["body"].as_str().unwrap());
    }
}

#[test]
fn the_contract_number_is_compared_and_refused_as_java_does() {
    let reference = reference();
    let cases = reference["contract"].as_array().unwrap();
    assert!(cases.len() >= 16);
    for case in cases {
        let announced = case["announced"].as_str();
        let compatible = case["compatible"].as_bool().unwrap();
        assert_eq!(server::contract_is_compatible(announced), compatible, "{announced:?}");
        if !compatible {
            let refusal = refusals::incompatible_contract(announced);
            assert_eq!(
                (refusal.status, refusal.reason.as_str()),
                (409, case["reason"].as_str().unwrap()),
                "{announced:?}"
            );
        }
    }
}

fn outcome_of<T>(read: Result<Option<T>, impl std::fmt::Debug>, fields: impl Fn(&T) -> Value) -> Value {
    match read {
        Ok(Some(value)) => json!({"outcome": "read", "read": fields(&value)}),
        Ok(None) => json!({"outcome": "null"}),
        Err(_) => json!({"outcome": "refused"}),
    }
}

fn expected(case: &Value) -> Value {
    match case["outcome"].as_str().unwrap() {
        "read" => json!({"outcome": "read", "read": case["read"]}),
        other => json!({"outcome": other}),
    }
}

#[test]
fn the_hello_is_read_as_spring_mvc_binds_it() {
    let reference = reference();
    for case in reference["hello_requests"].as_array().unwrap() {
        let read = HelloRequest::read(case["body"].as_str().unwrap().as_bytes());
        let outcome = outcome_of(read, |hello| {
            json!({"contractVersion": hello.contract_version, "sealingPublicKey": hello.sealing_public_key, "hostname": hello.hostname,
                "platform": hello.platform, "version": hello.version, "scannerEngine": hello.scanner_engine,
                "capabilities": hello.capabilities})
        });
        assert_eq!(outcome, expected(case), "{}", case["name"]);
    }
}

#[test]
fn the_sealing_key_announcement_is_read_as_spring_mvc_binds_it() {
    let reference = reference();
    for case in reference["sealing_key_requests"].as_array().unwrap() {
        let read = SealingKeyRequest::read(case["body"].as_str().unwrap().as_bytes());
        let outcome = outcome_of(
            read,
            |request| json!({"publicKey": request.public_key, "generation": request.generation, "signature": request.signature}),
        );
        assert_eq!(outcome, expected(case), "{}", case["name"]);
    }
    let usable = |body: &str| SealingKeyRequest::read(body.as_bytes()).unwrap().unwrap().has_usable_generation();
    assert!(usable(r#"{"generation":1}"#));
    assert!(!usable(r#"{"generation":0}"#) && !usable("{}"));
}

#[test]
fn the_failure_report_is_read_as_the_service_reads_it() {
    let reference = reference();
    let unreadable = refusals::failure_unreadable().reason;
    for case in reference["failure_reports"].as_array().unwrap() {
        let outcome = match FailureReport::read(case["body"].as_str().unwrap().as_bytes()) {
            Ok(report) => json!({"outcome": "read", "read": {"attempt": report.attempt, "reason": report.reason,
                "kind": match report.kind { FailureKind::Permanent => "permanent", FailureKind::Transient => "transient" }}}),
            Err(Unreadable::Refused(reason)) if reason == unreadable => json!({"outcome": "unreadable"}),
            Err(_) => json!({"outcome": "refused"}),
        };
        assert_eq!(outcome, expected(case), "{}", case["name"]);
    }
}

#[test]
fn the_failure_report_s_answer_is_written_as_spring_mvc_writes_it() {
    let reference = reference();
    for case in reference["failure_answers"].as_array().unwrap() {
        let java = case["body"].as_str().unwrap();
        let fields: Value = serde_json::from_str(java).unwrap();
        let retry_at = case.get("retry_at_epoch_second").map(|second| Instant {
            epoch_second: second.as_i64().unwrap(),
            nano: u32::try_from(case["retry_at_nano"].as_u64().unwrap()).unwrap(),
        });
        let answer = FailureAnswer {
            retried: fields["retried"].as_bool().unwrap(),
            attempt: i32::try_from(fields["attempt"].as_i64().unwrap()).unwrap(),
            max_attempts: i32::try_from(fields["maxAttempts"].as_i64().unwrap()).unwrap(),
            permanent: fields["permanent"].as_bool().unwrap(),
            retry_at,
        };
        assert_eq!(answer.to_body().unwrap(), java, "{}", case["name"]);
    }
}

#[test]
fn each_refusal_is_worded_as_the_controller_words_it() {
    let reference = reference();
    let java = &reference["refusals"];
    let agent = java["agent_name"].as_str().unwrap();
    let ours: [(&str, RouteRefusal); 13] = [
        ("sealing_key_unreadable", refusals::sealing_key_unreadable()),
        ("sealing_key_not_pinned", refusals::sealing_key_not_pinned(agent)),
        ("sealing_key_not_verified", refusals::sealing_key_not_verified(agent)),
        ("sealing_key_stale", refusals::sealing_key_stale(agent)),
        ("result_not_attested", refusals::result_not_attested(agent)),
        ("result_unreadable", refusals::result_unreadable()),
        ("result_no_longer_yours", refusals::result_no_longer_yours()),
        ("failure_not_attested", refusals::failure_not_attested(agent)),
        ("failure_unreadable", refusals::failure_unreadable()),
        ("failure_no_longer_yours", refusals::failure_no_longer_yours()),
        ("heartbeat_lease_lost", refusals::lease_lost()),
        ("not_an_agent", refusals::not_an_agent()),
        ("disabled", refusals::disabled(agent)),
    ];
    for (name, refusal) in ours {
        assert_eq!(json!({"status": refusal.status, "reason": refusal.reason}), java[name], "{name}");
    }
}

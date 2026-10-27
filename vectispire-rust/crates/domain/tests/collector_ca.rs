//! The collector CA: `CollectorCaTest`'s cases on the certificates of `reference/siem/collector-ca/` (written once
//! by BouncyCastle, `generate.jsh`), and every answer of `SiemReferenceSetTest` for the bundles built from them —
//! the subject as `X500Name` renders it, the dates, the DER, and each refusal's sentence.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vectispire_domain::instant::Instant;
use vectispire_domain::siem::CollectorCa;
use vectispire_domain::siem::collector_ca::{MAX_CERTIFICATES, MAX_LENGTH};

/// `2026-10-01T12:00:00Z`, `CollectorCaTest`'s `NOW`.
const NOW: Instant = Instant { epoch_second: 1_790_856_000, nano: 0 };

fn fixture(name: &str) -> String {
    vectispire_testkit::read(&format!("siem/collector-ca/{name}"))
}

fn refusal(pem: &str) -> String {
    CollectorCa::parse(Some(pem), NOW).unwrap_err().0
}

#[test]
fn a_ca_certificate_in_pem_is_read_its_subject_its_expiry_its_der() {
    let pem = fixture("01-root.pem");
    let ca = CollectorCa::parse(Some(&format!("\n{pem}\n")), NOW).unwrap();
    assert_eq!(ca.subject(), "CN=Corp Root");
    assert_eq!(ca.not_after().to_java_string().as_deref(), Some("2036-01-01T00:00:00Z"));
    assert_eq!(ca.anchors().len(), 1);
    assert!(!ca.anchors()[0].der.is_empty());
    assert_eq!(ca.pem(), pem.trim());
}

#[test]
fn a_bundle_is_read_whole_and_its_earliest_expiry_is_the_one_that_counts() {
    let ca = CollectorCa::parse(Some(&(fixture("01-root.pem") + &fixture("02-issuing.pem"))), NOW).unwrap();
    let subjects: Vec<&str> = ca.anchors().iter().map(|anchor| anchor.subject.as_str()).collect();
    assert_eq!(subjects, ["CN=Corp Root", "CN=Corp Issuing"]);
    assert_eq!(ca.not_after().to_java_string().as_deref(), Some("2027-01-01T00:00:00Z"));
}

#[test]
fn the_collector_s_own_certificate_is_refused_it_is_not_a_ca() {
    assert!(refusal(&fixture("03-leaf.pem")).contains("is not a certificate authority"));
}

#[test]
fn a_ca_whose_key_usage_forbids_signing_certificates_is_refused() {
    assert!(refusal(&fixture("04-no-keycertsign.pem")).contains("keyCertSign"));
}

#[test]
fn an_expired_ca_is_refused_at_the_save_though_a_tls_stack_would_accept_it_as_an_anchor() {
    let expired = fixture("05-expired.pem");
    assert!(refusal(&expired).contains("expired on"));
    // Still readable, so a stored one that has since expired can be shown and replaced.
    assert_eq!(CollectorCa::read(Some(&expired)).unwrap().subject(), "CN=Old Root");
}

#[test]
fn a_ca_not_valid_yet_is_refused() {
    assert!(refusal(&fixture("06-future.pem")).contains("not valid before"));
}

#[test]
fn a_private_key_is_refused_and_not_echoed_back() {
    // A PKCS#8 shape around invented bytes — version, the EC algorithm and P-256, an octet string that is no key —
    // its armour spelled at run time so that no file carries a key block.
    let mut der = vec![0x30, 0x3c, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    der.extend([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x22]);
    der.extend(b"invented-not-a-key-0123456789abcd");
    der.push(b'!');
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(&der);
    let label = ["PRIVATE", "KEY"].join(" ");
    let key = format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n");
    let refused = refusal(&key);
    assert!(refused.contains("a private key never belongs here"), "{refused}");
    assert!(!refused.contains(&body[..24]));
}

#[test]
fn text_with_no_certificate_garbage_inside_the_armour_and_an_oversized_bundle_are_refused() {
    assert!(refusal("hello").contains("holds no certificate"));
    assert!(
        refusal("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
            .contains("not a readable PEM certificate")
    );
    assert!(refusal(" ").contains("empty"));
    assert!(refusal(&"x".repeat(MAX_LENGTH + 1)).contains(&format!("at most {MAX_LENGTH}")));
}

#[test]
fn a_bundle_of_more_certificates_than_a_chain_needs_is_refused() {
    let one = fixture("01-root.pem");
    assert_eq!(CollectorCa::parse(Some(&one.repeat(MAX_CERTIFICATES)), NOW).unwrap().anchors().len(), MAX_CERTIFICATES);
    assert!(refusal(&one.repeat(MAX_CERTIFICATES + 1)).contains(&format!("more than {MAX_CERTIFICATES}")));
}

/// A case's text, built as the Java writer builds it.
fn bundle(case: &Value) -> Option<String> {
    if case["absent"].as_bool() == Some(true) {
        return None;
    }
    let mut text = String::new();
    for part in case["parts"].as_array().unwrap() {
        if let Some(literal) = part["text"].as_str() {
            text.push_str(literal);
            continue;
        }
        let mut fixture = fixture(part["file"].as_str().unwrap());
        if let Some(replace) = part["replace"].as_array() {
            fixture = fixture.replace(replace[0].as_str().unwrap(), replace[1].as_str().unwrap());
        }
        text.push_str(&fixture.repeat(part["repeat"].as_u64().unwrap_or(1) as usize));
    }
    Some(text)
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn every_bundle_is_read_as_the_java_side_reads_it() {
    let inputs = vectispire_testkit::read_json("siem/inputs.json");
    let answers = vectispire_testkit::read_json("siem/java-answers.json");
    let now = Instant {
        epoch_second: inputs["collectorCa"]["now"][0].as_i64().unwrap(),
        nano: inputs["collectorCa"]["now"][1].as_u64().unwrap() as u32,
    };
    let cases = inputs["collectorCa"]["cases"].as_array().unwrap();
    let expected = answers["collectorCa"].as_array().unwrap();
    assert_eq!(cases.len(), expected.len(), "java-answers.json is regenerated after inputs.json");
    let mut differences = Vec::new();
    for (case, java) in cases.iter().zip(expected) {
        let pem = bundle(case);
        let mut rust = json!({"name": case["name"]});
        match CollectorCa::read(pem.as_deref()) {
            Ok(read) => {
                let anchors: Vec<Value> = read
                    .anchors()
                    .iter()
                    .map(|anchor| {
                        json!({
                            "subject": anchor.subject,
                            "notBefore": anchor.not_before.to_java_string(),
                            "notAfter": anchor.not_after.to_java_string(),
                            "derSha256": sha256(&anchor.der),
                        })
                    })
                    .collect();
                rust["read"] = json!({
                    "pemSha256": sha256(read.pem().as_bytes()),
                    "subject": read.subject(),
                    "notAfter": read.not_after().to_java_string(),
                    "anchors": anchors,
                });
            }
            Err(refused) => rust["readRefused"] = json!(refused.0),
        }
        rust["parse"] = json!(match CollectorCa::parse(pem.as_deref(), now) {
            Ok(_) => "accepted".to_owned(),
            Err(refused) => refused.0,
        });
        if &rust != java {
            differences.push(format!("{}:\n  java {java}\n  rust {rust}", case["name"]));
        }
    }
    assert!(differences.is_empty(), "{} difference(s):\n{}", differences.len(), differences.join("\n"));
}

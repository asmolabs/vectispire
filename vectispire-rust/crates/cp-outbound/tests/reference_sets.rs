//! The guard, the reserved endpoints and the address classes against what the Java classes answer
//! (`OutboundGuardReferenceSetTest` writes `reference/outbound/*-expected.json`; this reads them).
//!
//! A difference here is not a style question: a URL the Java guard refuses and this one lets through
//! is an SSRF the port introduced, and one it refuses where Java allows is a setting that stops
//! working on the day of the switch. Add the input that tells the two apart to `*-inputs.json`,
//! regenerate on the Java side, and make this agree.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use vectispire_cp_outbound::address::{self, Raw};
use vectispire_cp_outbound::guard::{OutboundUrlGuard, ReservedEndpoint};
use vectispire_cp_outbound::policy::OutboundPolicy;
use vectispire_cp_outbound::reserved;
use vectispire_domain::net::parse_literal;
use vectispire_testkit::read_json;

fn raw_of_hex(hex: &str) -> Raw {
    let bytes: Vec<u8> =
        (0..hex.len()).step_by(2).map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap()).collect();
    match bytes.len() {
        4 => Raw::V4(bytes.try_into().unwrap()),
        16 => Raw::V6(bytes.try_into().unwrap()),
        other => panic!("{other} bytes is not an address"),
    }
}

fn guards(inputs: &Value) -> Vec<(String, OutboundUrlGuard)> {
    let table: std::collections::HashMap<String, Vec<Raw>> = inputs["resolver"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, addresses)| {
            (name.clone(), addresses.as_array().unwrap().iter().map(|a| raw_of_hex(a.as_str().unwrap())).collect())
        })
        .collect();
    inputs["reserved_sets"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, endpoints)| {
            let reserved = endpoints
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    ReservedEndpoint::new(
                        e["host"].as_str().unwrap(),
                        e["port"].as_i64().unwrap() as i32,
                        e["what"].as_str().unwrap(),
                    )
                })
                .collect();
            let table = table.clone();
            // A fixed table of names and, for anything it does not hold, the literal reading the real
            // resolver does first — no answer depends on a DNS server.
            let resolver = move |hostname: &str| -> Vec<Raw> {
                if let Some(addresses) = table.get(hostname) {
                    return addresses.clone();
                }
                parse_literal(hostname).map(|literal| vec![Raw::of(literal)]).unwrap_or_default()
            };
            (name.clone(), OutboundUrlGuard::with_resolver(resolver, reserved))
        })
        .collect()
}

fn record(
    result: Result<vectispire_cp_outbound::Destination, vectispire_cp_outbound::UnsafeUrl>,
) -> (&'static str, Value) {
    match result {
        Ok(destination) => (
            "ok",
            json!({
                "url": destination.url,
                "host": destination.host,
                "addresses": destination.addresses.iter().map(|ip| Raw::of(*ip).text()).collect::<Vec<_>>(),
            }),
        ),
        Err(refused) => ("refused", Value::String(refused.0)),
    }
}

fn compare(what: &str, expected: &Value, actual: &Value) {
    if expected == actual {
        return;
    }
    // Every case that differs, by its input — not a 300 KB dump of both.
    let (left, right) = (expected.as_array().unwrap(), actual.as_array().unwrap());
    assert_eq!(left.len(), right.len(), "{what}: the number of cases");
    let differing: Vec<String> = left
        .iter()
        .zip(right)
        .filter(|(java, rust)| java != rust)
        .map(|(java, rust)| {
            let key =
                java.get("url").or_else(|| java.get("host")).or_else(|| java.get("input")).or_else(|| java.get("hex"));
            let run = java["runs"]
                .as_array()
                .zip(rust["runs"].as_array())
                .and_then(|(j, r)| j.iter().zip(r).find(|(a, b)| a != b));
            format!("{key:?}\n   java: {:?}\n   rust: {:?}", run.map(|r| r.0), run.map(|r| r.1))
        })
        .collect();
    assert!(
        differing.is_empty(),
        "{what}: {} case(s) differ between Java and the Rust port:\n{}",
        differing.len(),
        differing.join("\n")
    );
}

/// The URLs the two read differently, each with why — and the Rust answer pinned, so a change in either
/// is noticed rather than absorbed.
///
/// `http://[fe80::1%eth0]/`: the JDK's URI parser accepts a scope id inside the brackets, and its
/// answer then depends on the machine — `InetAddress.ofLiteral` refuses a scope naming no interface, so
/// the literal reads as an unresolvable *name* and passes under the policies that tolerate one, and on
/// a host that has `eth0` it is link-local and refused. The Rust port's `java_uri` parser (in the
/// agent's `domain` crate, which this crate does not change) does not take a scope id, so the URL is
/// unreadable here, on every machine: the safe side of the difference, and a URL no setting needs.
const KNOWN_DIFFERENCES: &[&str] = &["http://[fe80::1%eth0]/"];

#[test]
fn the_guard_decides_as_the_java_guard_does() {
    let inputs = read_json("outbound/guard-inputs.json");
    let expected = read_json("outbound/guard-expected.json");
    let label = inputs["label"].as_str().unwrap();
    let guards = guards(&inputs);

    let mut urls = Vec::new();
    for input in inputs["urls"].as_array().unwrap() {
        let url: Option<&str> = input.as_str();
        let mut runs = Vec::new();
        for policy in OutboundPolicy::ALL {
            for (set, guard) in &guards {
                // `null` is an empty value to the Java guard (`url == null ? "" : url.trim()`).
                let (kind, value) = record(guard.validate_and_resolve(url.unwrap_or(""), policy, label));
                runs.push(json!({"policy": policy.name(), "reserved": set, kind: value}));
            }
        }
        urls.push(json!({"url": url, "runs": runs}));
    }
    let known = |entry: &Value| KNOWN_DIFFERENCES.contains(&entry["url"].as_str().unwrap_or_default());
    for entry in urls.iter().filter(|entry| known(entry)) {
        for run in entry["runs"].as_array().unwrap() {
            assert_eq!(run["refused"], "Webhook URL: unreadable URL.", "known difference {}", entry["url"]);
        }
    }
    let rust: Vec<Value> = urls.into_iter().filter(|entry| !known(entry)).collect();
    let java: Vec<Value> = expected["urls"].as_array().unwrap().iter().filter(|entry| !known(entry)).cloned().collect();
    compare("urls", &Value::Array(java), &Value::Array(rust));

    let mut endpoints = Vec::new();
    for input in inputs["endpoints"].as_array().unwrap() {
        let host = input["host"].as_str();
        let port = input["port"].as_i64().unwrap();
        let mut runs = Vec::new();
        for policy in OutboundPolicy::ALL {
            for (set, guard) in &guards {
                let (kind, value) = record(guard.validate_and_resolve_endpoint(host, port, policy, label));
                runs.push(json!({"policy": policy.name(), "reserved": set, kind: value}));
            }
        }
        endpoints.push(json!({"host": host, "port": port, "runs": runs}));
    }
    compare("endpoints", &expected["endpoints"], &Value::Array(endpoints));
}

fn endpoints_value(
    reading: Result<Vec<ReservedEndpoint>, reserved::ReservedError>,
    entry: &mut serde_json::Map<String, Value>,
) {
    match reading {
        Ok(endpoints) => {
            let list: Vec<Value> =
                endpoints.iter().map(|e| json!({"host": e.host, "port": e.port, "what": e.what})).collect();
            entry.insert("endpoints".to_owned(), Value::Array(list));
        }
        Err(error) => {
            entry.insert("error".to_owned(), Value::String(error.0));
        }
    }
}

#[test]
fn the_reserved_endpoints_are_read_as_the_java_classes_read_them() {
    let inputs = read_json("outbound/reserved-inputs.json");
    let expected = read_json("outbound/reserved-expected.json");

    let mut docker = Vec::new();
    for input in inputs["docker_hosts"].as_array().unwrap() {
        let mut entry = serde_json::Map::new();
        entry.insert("input".to_owned(), input.clone());
        endpoints_value(reserved::of_docker_host(input.as_str()), &mut entry);
        docker.push(Value::Object(entry));
    }
    compare("docker_hosts", &expected["docker_hosts"], &Value::Array(docker));

    let mut datasources = Vec::new();
    for input in inputs["datasources"].as_array().unwrap() {
        let mut entry = serde_json::Map::new();
        entry.insert("input".to_owned(), input.clone());
        endpoints_value(reserved::of_datasource(input.as_str()), &mut entry);
        datasources.push(Value::Object(entry));
    }
    compare("datasources", &expected["datasources"], &Value::Array(datasources));

    let mut kubernetes = Vec::new();
    for input in inputs["kubernetes"].as_array().unwrap() {
        let host = input[0].as_str();
        let port = input.get(1).and_then(Value::as_str);
        let mut entry = serde_json::Map::new();
        entry.insert("host".to_owned(), host.map_or(Value::Null, Value::from));
        entry.insert("port".to_owned(), port.map_or(Value::Null, Value::from));
        endpoints_value(reserved::of_kubernetes_service(host, port), &mut entry);
        kubernetes.push(Value::Object(entry));
    }
    compare("kubernetes", &expected["kubernetes"], &Value::Array(kubernetes));
}

#[test]
fn the_address_classes_are_the_java_classes() {
    let inputs = read_json("outbound/addresses-inputs.json");
    let expected = read_json("outbound/addresses-expected.json");
    let mut actual = Vec::new();
    for input in inputs.as_array().unwrap() {
        let hex = input.as_str().unwrap();
        let raw = raw_of_hex(hex);
        actual.push(json!({
            "hex": hex,
            "text": raw.text(),
            "link_local": address::is_link_local(raw),
            "metadata": address::is_metadata(raw),
            "unspecified": address::is_unspecified(raw),
            "loopback": address::is_loopback(raw),
            "global": address::is_global(raw),
        }));
    }
    compare("addresses", &expected, &Value::Array(actual));
}

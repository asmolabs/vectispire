//! The SIEM domain against `SiemReferenceSetTest`'s answers for `reference/siem/inputs.json`: the catalogue, every
//! audit operation's signal, the CEF lines, the syslog frames, the endpoints and their refusals, the protocols,
//! the severity minimums and the triage signals — byte for byte, since each of them leaves the system.

use serde_json::{Value, json};
use vectispire_domain::instant::Instant;
use vectispire_domain::severity::Severity;
use vectispire_domain::siem::endpoint::{self, SiemEndpoint};
use vectispire_domain::siem::{
    CefEvent, SecurityEventType, SiemProtocol, severity_filter, signalled_by, syslog, triage_signals,
};

fn text(value: &Value) -> Option<&str> {
    value.as_str()
}

fn severity(name: &str) -> Severity {
    match name {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        "NEGLIGIBLE" => Severity::Negligible,
        "UNKNOWN" => Severity::Unknown,
        other => panic!("no severity {other}"),
    }
}

const SEVERITIES: [&str; 6] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"];

/// The event a case describes, as the Java writer builds it.
fn event(input: &Value) -> Result<CefEvent, String> {
    let kind = SecurityEventType::from_wire_name(input["type"].as_str().unwrap()).unwrap();
    let at = Instant { epoch_second: input["at"][0].as_i64().unwrap(), nano: input["at"][1].as_u64().unwrap() as u32 };
    if let Some(severity) = input.get("construct") {
        return CefEvent::new(kind, at, None, &[], severity.as_i64().unwrap() as i32).map_err(|refused| refused.0);
    }
    let mut builder = CefEvent::builder(kind, at);
    if let Some(issue) = input.get("issueSeverity") {
        builder = builder.issue_severity(severity(issue.as_str().unwrap()));
    }
    for call in input["calls"].as_array().into_iter().flatten() {
        let first = text(&call[1]);
        builder = match call[0].as_str().unwrap() {
            "message" => builder.message(first),
            "user" => builder.user(first),
            "sourceIp" => builder.source_ip(first),
            "action" => builder.action(first),
            "externalId" => builder.external_id(first),
            "target" => builder.target(first),
            "userAgent" => builder.user_agent(first),
            "identifier" => builder.identifier(first),
            "component" => builder.component(first),
            // Java's `extension` ignores a null key; a key is never absent here.
            "extension" => match first {
                Some(key) => builder.extension(key, text(&call[2])),
                None => builder,
            },
            other => panic!("no builder method {other}"),
        };
    }
    builder.build().map_err(|refused| refused.0)
}

struct Differences(Vec<String>);

impl Differences {
    fn check(&mut self, what: String, java: &Value, rust: &Value) {
        if java != rust {
            self.0.push(format!("{what}:\n  java {java}\n  rust {rust}"));
        }
    }
}

#[test]
fn the_siem_domain_answers_as_the_java_side_answers() {
    let inputs = vectispire_testkit::read_json("siem/inputs.json");
    let answers = vectispire_testkit::read_json("siem/java-answers.json");
    let mut differences = Differences(Vec::new());

    let catalogue: Vec<Value> = SecurityEventType::ALL
        .iter()
        .map(|kind| {
            json!({
                "name": kind.wire_name(),
                "signatureId": kind.signature_id(),
                "description": kind.description(),
                "cefSeverity": kind.cef_severity(),
                "outcome": kind.outcome().wire_name(),
                "followsIssueSeverity": kind.follows_issue_severity(),
            })
        })
        .collect();
    differences.check("catalogue".into(), &answers["catalogue"], &Value::from(catalogue));

    let signalled = answers["signalledBy"].as_array().unwrap();
    assert!(signalled.len() > 100, "every audit operation is in the set");
    for answer in signalled {
        let operation = answer["operation"].as_str().unwrap();
        let rust = signalled_by(operation).map(SecurityEventType::wire_name);
        differences.check(format!("signalledBy {operation}"), &answer["event"], &json!(rust));
    }

    let cef_inputs = inputs["cef"].as_array().unwrap();
    assert_eq!(
        cef_inputs.len(),
        answers["cef"].as_array().unwrap().len(),
        "java-answers.json is regenerated after inputs.json"
    );
    for (input, answer) in cef_inputs.iter().zip(answers["cef"].as_array().unwrap()) {
        let rust = match event(input) {
            Ok(event) => json!({"name": input["name"], "line": event.to_cef_string(text(&input["version"]))}),
            Err(refused) => json!({"name": input["name"], "refused": refused}),
        };
        differences.check(format!("cef {}", input["name"]), answer, &rust);
    }

    for (input, answer) in inputs["syslog"].as_array().unwrap().iter().zip(answers["syslog"].as_array().unwrap()) {
        let event = event(input).unwrap();
        let message = syslog::format(&event, text(&input["hostname"]), input["cef"].as_str().unwrap());
        differences.check(
            format!("syslog {}", input["name"]),
            answer,
            &json!({"name": input["name"], "message": message}),
        );
    }

    for (input, answer) in inputs["frames"].as_array().unwrap().iter().zip(answers["frames"].as_array().unwrap()) {
        let frame = syslog::octet_counted(input.as_str().unwrap());
        let rust = json!({"bytes": frame.len(), "frame": String::from_utf8(frame).unwrap()});
        differences.check(format!("frame {input}"), answer, &rust);
    }

    let endpoint_inputs = inputs["endpoints"].as_array().unwrap();
    assert_eq!(endpoint_inputs.len(), answers["endpoints"].as_array().unwrap().len());
    for (input, answer) in endpoint_inputs.iter().zip(answers["endpoints"].as_array().unwrap()) {
        let protocol = SiemProtocol::by_name(input["protocol"].as_str()).unwrap();
        let mut rust = json!({"protocol": input["protocol"], "endpoint": input["endpoint"]});
        match endpoint::parse(protocol, text(&input["endpoint"])) {
            Ok(SiemEndpoint::Webhook { url }) => rust["webhook"] = json!(url),
            Ok(SiemEndpoint::Syslog { protocol, host, port }) => {
                rust["syslog"] = json!({"protocol": protocol.name(), "host": host, "port": port});
            }
            Err(refused) => rust["refused"] = json!(refused.0),
        }
        differences.check(format!("endpoint {} {}", input["protocol"], input["endpoint"]), answer, &rust);
    }

    for (input, answer) in inputs["protocols"].as_array().unwrap().iter().zip(answers["protocols"].as_array().unwrap())
    {
        let protocol = SiemProtocol::by_name(text(input));
        let rust = json!({
            "value": input,
            "protocol": protocol.map(SiemProtocol::name),
            "carriesHeaders": protocol.map(SiemProtocol::carries_headers),
        });
        differences.check(format!("protocol {input}"), answer, &rust);
    }

    for (input, answer) in inputs["minimums"].as_array().unwrap().iter().zip(answers["minimums"].as_array().unwrap()) {
        let stored = text(input);
        let mut admitted: Vec<String> = SecurityEventType::ALL
            .iter()
            .filter(|kind| {
                severity_filter::admits(
                    &CefEvent::builder(**kind, Instant::of_epoch_second(0)).build().unwrap(),
                    stored,
                )
            })
            .map(|kind| kind.wire_name().to_owned())
            .collect();
        for name in SEVERITIES {
            let breach = CefEvent::builder(SecurityEventType::SlaBreached, Instant::of_epoch_second(0))
                .issue_severity(severity(name))
                .build()
                .unwrap();
            if severity_filter::admits(&breach, stored) {
                admitted.push(format!("SLA_BREACHED/{name}"));
            }
        }
        let rust = json!({"value": input, "floor": severity_filter::minimum_of(stored), "admits": admitted});
        differences.check(format!("minimum {input}"), answer, &rust);
    }

    for (input, answer) in inputs["triage"].as_array().unwrap().iter().zip(answers["triage"].as_array().unwrap()) {
        let previous: Vec<Option<&str>> = input["previous"].as_array().unwrap().iter().map(text).collect();
        let rust = triage_signals::of(&previous, text(&input["result"])).map(SecurityEventType::wire_name);
        differences.check(format!("triage {input}"), answer, &json!({"event": rust}));
    }

    assert!(differences.0.is_empty(), "{} difference(s):\n{}", differences.0.len(), differences.0.join("\n"));
}

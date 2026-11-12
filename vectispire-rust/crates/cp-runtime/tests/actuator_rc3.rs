//! The actuator's answers against what the Java control plane answered — recorded from the 0.11.0-rc.3 image
//! (`reference/actuator/rc3-answers.json`): the status, the content type and the **bytes** of each document,
//! key order included. A probe, a dashboard and the operator's `curl | jq` all read these.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use vectispire_cp_runtime::actuator::{Actuator, BuildInfo, Health};
use vectispire_cp_runtime::metrics::Metrics;
use vectispire_testkit::read_json;

#[test]
fn every_recorded_answer_is_reproduced_byte_for_byte() {
    let recorded = read_json("actuator/rc3-answers.json");
    let build = &recorded["build"];
    let text = |value: &serde_json::Value| value.as_str().unwrap().to_owned();

    let metrics = Arc::new(Metrics::new("vectispire"));
    metrics.gauge("vectispire.scans.queued", "Scans waiting for a worker or an agent to claim them", || 0.0);
    let actuator = Actuator {
        health: Arc::new(Health::default()),
        metrics,
        build: BuildInfo {
            group: text(&build["group"]),
            artifact: text(&build["artifact"]),
            name: text(&build["name"]),
            version: text(&build["version"]),
            time: None,
        },
    };

    let cases = recorded["cases"].as_array().unwrap();
    assert!(cases.len() >= 8, "{} recorded answers", cases.len());
    for case in cases {
        let path = case["path"].as_str().unwrap();
        let base = recorded["base_url"].as_str().unwrap();
        let answer = actuator
            .answer(path, case["query"].as_str().unwrap(), base)
            .unwrap_or_else(|| panic!("{path}: not answered"));
        assert_eq!(u64::from(answer.status), case["status"].as_u64().unwrap(), "{path}: status");
        assert_eq!(answer.content_type, case["content_type"].as_str(), "{path}: content type");
        assert_eq!(answer.body, case["body"].as_str().unwrap(), "{path}: body");
    }
}

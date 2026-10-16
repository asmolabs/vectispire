//! The URL checks against `RepositoryUrl`'s answers for `reference/repository-url/inputs.json` —
//! the URLs that tell two URL parsers apart. Whoever finds another adds it to the inputs, runs the
//! Java side's `RepositoryUrlReferenceSetTest` in write mode, and this test holds the port to it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vectispire_domain::repository_url;

#[test]
fn every_url_is_judged_as_the_java_side_judges_it() {
    let expected = vectispire_testkit::read_json("repository-url/expected.json");
    let inputs = vectispire_testkit::read_json("repository-url/inputs.json");
    let answers = expected.as_array().unwrap();
    assert_eq!(answers.len(), inputs.as_array().unwrap().len(), "expected.json is regenerated after inputs.json");
    let mut differences = Vec::new();
    for answer in answers {
        let url = answer["url"].as_str().unwrap();
        let ours = serde_json::json!({
            "url": url,
            "validate": repository_url::validate(url),
            "host": repository_url::host(url),
            "redact": repository_url::redact(url),
            "is_https": repository_url::is_https(url),
            "has_host_gitlab_example_org": repository_url::has_host(url, "gitlab.example.org"),
        });
        for field in ["validate", "host", "redact", "is_https", "has_host_gitlab_example_org"] {
            if ours[field] != answer[field] {
                differences.push(format!("{url:?} {field}: java {} rust {}", answer[field], ours[field]));
            }
        }
    }
    assert!(differences.is_empty(), "{} difference(s):\n{}", differences.len(), differences.join("\n"));
}

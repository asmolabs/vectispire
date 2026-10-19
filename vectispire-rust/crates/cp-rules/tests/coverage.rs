//! Unit tests for rule coverage assessment and OWASP categories.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use vectispire_cp_rules::{
    StoredFile,
    coverage::{
        BUNDLED_PYTHON_RULE, BUNDLED_RULES, State, assess, declared_owasp_categories,
        declared_owasp_categories_by_language, ecosystem_of, language_of, rule_tree_path,
    },
};

#[test]
fn unconfigured_when_no_rules_installed() {
    let bundled: Vec<String> = BUNDLED_RULES.iter().map(|s| (*s).to_owned()).collect();
    let purls = vec!["pkg:maven/org.springframework/spring-core@6.0.0".to_owned()];

    let assessment = assess(&bundled, &purls);
    assert_eq!(assessment.state, State::Unconfigured);
    assert!(assessment.languages_with_rules.contains("python"));
}

#[test]
fn sees_installed_set_language_through_original_name() {
    let file = StoredFile {
        path: "rule-0001.yaml".to_owned(),
        original_name: Some("java/xss/reflected.yaml".to_owned()),
        content: "rules: []\n".to_owned(),
    };

    let tree_path = rule_tree_path(&file);
    assert_eq!(tree_path, "semgrep/java/xss/reflected.yaml");

    let mut paths: Vec<String> = BUNDLED_RULES.iter().map(|s| (*s).to_owned()).collect();
    paths.push(tree_path);

    // With Java in inventory
    let purls = vec!["pkg:maven/org.springframework/spring-core@6.0.0".to_owned()];
    let assessment = assess(&paths, &purls);

    assert_ne!(assessment.state, State::Unconfigured);
    assert_eq!(assessment.state, State::Covered);
    assert!(assessment.languages_with_rules.contains("java"));
    assert!(assessment.languages_with_rules.contains("python"));
}

#[test]
fn a_flat_name_declares_no_language() {
    let file = StoredFile {
        path: "rule-0001.yaml".to_owned(),
        original_name: Some("injection.yaml".to_owned()),
        content: "rules: []\n".to_owned(),
    };

    let tree_path = rule_tree_path(&file);
    assert_eq!(tree_path, "rule-0001.yaml");
    assert_eq!(language_of(&tree_path), None);

    let mut paths: Vec<String> = BUNDLED_RULES.iter().map(|s| (*s).to_owned()).collect();
    paths.push(tree_path);

    let purls = vec!["pkg:maven/org.springframework/spring-core@6.0.0".to_owned()];
    let assessment = assess(&paths, &purls);

    // Still unconfigured because no new language was discovered
    assert_eq!(assessment.state, State::Unconfigured);
}

#[test]
fn partial_coverage_when_an_ecosystem_lacks_rules() {
    let file = StoredFile {
        path: "rule-0001.yaml".to_owned(),
        original_name: Some("java/xss/reflected.yaml".to_owned()),
        content: "rules: []\n".to_owned(),
    };
    let mut paths: Vec<String> = BUNDLED_RULES.iter().map(|s| (*s).to_owned()).collect();
    paths.push(rule_tree_path(&file));

    // Inventory has both Java (maven) and Go (golang)
    let purls = vec![
        "pkg:maven/org.springframework/spring-core@6.0.0".to_owned(),
        "pkg:golang/github.com/gin-gonic/gin@v1.9.0".to_owned(),
    ];
    let assessment = assess(&paths, &purls);

    assert_eq!(assessment.state, State::Partial);
    assert!(assessment.uncovered.contains("golang"));
}

#[test]
fn extracts_ecosystem_from_purl() {
    assert_eq!(ecosystem_of("pkg:maven/org.acme/foo@1.0"), Some("maven".to_owned()));
    assert_eq!(ecosystem_of("pkg:npm/express@4.18.2"), Some("npm".to_owned()));
    assert_eq!(ecosystem_of("pkg:pypi/requests@2.31.0"), Some("pypi".to_owned()));
    assert_eq!(ecosystem_of("pkg:cargo/serde@1.0.197"), Some("cargo".to_owned()));
    assert_eq!(ecosystem_of("invalid:purl"), None);
}

#[test]
fn declared_owasp_categories_includes_bundled_and_installed() {
    // Shipped bundled rule declares A03
    let cats_bundled = declared_owasp_categories(vec![BUNDLED_PYTHON_RULE]);
    assert_eq!(cats_bundled, BTreeSet::from(["A03".to_owned()]));

    let custom_rule = r#"
rules:
  - id: team.ssrf
    metadata:
      owasp:
        - A10:2021 - Server-Side Request Forgery
"#;
    let cats = declared_owasp_categories(vec![BUNDLED_PYTHON_RULE, custom_rule]);
    assert_eq!(cats, BTreeSet::from(["A03".to_owned(), "A10".to_owned()]));
}

#[test]
fn declared_owasp_categories_by_language_groups_properly() {
    let custom_rule = r#"
rules:
  - id: java.ssrf
    metadata:
      owasp:
        - A10:2021
"#;
    let pairs =
        vec![("semgrep/python/dangerous-eval.yaml", BUNDLED_PYTHON_RULE), ("semgrep/java/ssrf.yaml", custom_rule)];

    let by_lang = declared_owasp_categories_by_language(pairs);
    assert_eq!(by_lang.get("python").unwrap(), &BTreeSet::from(["A03".to_owned()]));
    assert_eq!(by_lang.get("java").unwrap(), &BTreeSet::from(["A10".to_owned()]));
}

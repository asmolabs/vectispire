//! Unit tests for rule set file validation, caps, regex extraction, hashing and triage impact.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use vectispire_cp_rules::{
    UploadedFile,
    ruleset::{
        MAX_FILE_BYTES, MAX_FILES, accept, content_hash, impact, rule_ids_in, rule_ids_of, validate_activation_note,
        validate_name,
    },
};

fn upload(name: &str, content: &str) -> UploadedFile {
    UploadedFile { name: Some(name.to_owned()), content: Some(content.to_owned()) }
}

#[test]
fn accepts_valid_rule_files_and_renames_flat() {
    let uploads = vec![upload("../../../etc/passwd.yaml", "rules: []\n"), upload("ok.yml", "rules: []\n")];

    let stored = accept(&uploads).expect("valid rule set should be accepted");
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].path, "rule-0001.yaml");
    assert_eq!(stored[0].original_name.as_deref(), Some("../../../etc/passwd.yaml"));
    assert_eq!(stored[1].path, "rule-0002.yaml");
    assert_eq!(stored[1].original_name.as_deref(), Some("ok.yml"));
}

#[test]
fn refuses_empty_file_list() {
    let err = accept(&[]).expect_err("empty uploads should be refused");
    assert!(err.0.contains("No file was uploaded"));
}

#[test]
fn refuses_empty_file_content() {
    let uploads = vec![upload("a.yaml", "")];
    let err = accept(&uploads).expect_err("empty file content should be refused");
    assert!(err.0.contains("is empty"));
}

#[test]
fn refuses_non_yaml_extensions() {
    for name in &["rules.txt", "rules", "rules.yaml.exe", ""] {
        let uploads = vec![upload(name, "rules: []\n")];
        let err = accept(&uploads).expect_err("non-yaml file should be refused");
        assert!(err.0.contains("is not a YAML file"));
    }
}

#[test]
fn enforces_file_count_cap() {
    let uploads: Vec<UploadedFile> = (0..=MAX_FILES).map(|i| upload(&format!("{i}.yaml"), "rules: []\n")).collect();
    let err = accept(&uploads).expect_err("exceeding max file count must be refused");
    assert!(err.0.contains("Too many files"));
}

#[test]
fn enforces_file_size_cap() {
    let big_content = "x".repeat(MAX_FILE_BYTES + 1);
    let uploads = vec![upload("big.yaml", &big_content)];
    let err = accept(&uploads).expect_err("exceeding single file size cap must be refused");
    assert!(err.0.contains("over the"));
}

#[test]
fn extracts_rule_ids_with_regex() {
    let content = r#"
rules:
  - id: python.lang.security.dangerous-eval
    message: eval
  - id: "quoted.rule-id"
  -   id:   spaced.rule
    # id: commented-out-id
"#;
    let ids = rule_ids_in(content);
    assert!(ids.iter().any(|id| id == "python.lang.security.dangerous-eval"));
    assert!(ids.iter().any(|id| id == "quoted.rule-id"));
    assert!(ids.iter().any(|id| id == "spaced.rule"));
    assert!(!ids.iter().any(|id| id == "commented-out-id"));
}

#[test]
fn misses_in_rule_ids_are_harmless_and_empty_rules_are_still_accepted() {
    let empty_yaml = "rules:\n  - id: >\n      folded.id\n";
    assert!(rule_ids_in(empty_yaml).is_empty());

    // Still accepted by accept() — rule IDs are advisory for impact/counts only
    let uploads = vec![upload("advisory.yaml", empty_yaml)];
    let stored = accept(&uploads).expect("files without matched rule IDs are still accepted");
    assert_eq!(stored.len(), 1);
}

#[test]
fn deduplicates_rule_ids_across_files() {
    let uploads = vec![upload("a.yaml", "- id: shared\n"), upload("b.yaml", "- id: shared\n")];
    let stored = accept(&uploads).unwrap();
    let ids = rule_ids_of(&stored);
    assert_eq!(ids, vec!["shared".to_owned()]);
}

#[test]
fn content_hash_ignores_uploaded_names() {
    let set_a = accept(&[upload("first.yaml", "rules: []\n")]).unwrap();
    let set_b = accept(&[upload("renamed.yml", "rules: []\n")]).unwrap();

    let hash_a = content_hash(&set_a);
    let hash_b = content_hash(&set_b);
    assert_eq!(hash_a, hash_b);
}

#[test]
fn content_hash_follows_content_and_order() {
    let set_a = accept(&[upload("a.yaml", "- id: one\n"), upload("b.yaml", "- id: two\n")]).unwrap();
    let set_b = accept(&[upload("b.yaml", "- id: two\n"), upload("a.yaml", "- id: one\n")]).unwrap();

    let a = content_hash(&set_a);
    let b = content_hash(&set_b);
    assert_ne!(a, b);
}

#[test]
fn calculates_triage_impact_and_sorts_losing_rules() {
    let current_ids = BTreeSet::from(["kept".to_owned(), "dropped".to_owned()]);
    let next_ids = BTreeSet::from(["kept".to_owned(), "added".to_owned()]);

    let mut open_counts = BTreeMap::new();
    open_counts.insert("kept".to_owned(), 3_i64);
    open_counts.insert("dropped".to_owned(), 7_i64);

    let triage = impact(&current_ids, &next_ids, &open_counts);
    assert_eq!(triage.losing_issues, vec!["dropped".to_owned()]);
    assert_eq!(triage.affected_issues, 7);
    assert_eq!(triage.added_rules, 1);
    assert_eq!(triage.removed_rules, 1);

    // Sorts the warning
    let empty_current = BTreeSet::new();
    let empty_next = BTreeSet::new();
    let mut unsorted_counts = BTreeMap::new();
    unsorted_counts.insert("zulu".to_owned(), 1_i64);
    unsorted_counts.insert("alpha".to_owned(), 1_i64);
    unsorted_counts.insert("mike".to_owned(), 1_i64);

    let sorted_impact = impact(&empty_current, &empty_next, &unsorted_counts);
    assert_eq!(sorted_impact.losing_issues, vec!["alpha".to_owned(), "mike".to_owned(), "zulu".to_owned()]);
}

#[test]
fn validates_name_and_activation_note() {
    assert!(validate_name("   ").is_err());
    assert_eq!(validate_name("  OWASP Rules  ").unwrap(), "OWASP Rules");

    assert!(validate_activation_note(Some("   ")).unwrap().is_none());
    assert_eq!(
        validate_activation_note(Some("  Approved by Security Lead  ")).unwrap().as_deref(),
        Some("Approved by Security Lead")
    );
}

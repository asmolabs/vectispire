//! Tests for reading, selecting, and verifying the upstream Semgrep rules catalogue.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use vectispire_cp_rules::catalogue::{
    Entry, LICENCE, UPSTREAM, describe, is_gitleaks_duplicate, is_rule, licence_of, name_for, read_entries_from_dir,
    require_allowed, require_commit, select,
};

fn write_file(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(p, content).unwrap();
}

#[test]
fn reads_only_what_matters() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    write_file(root, "LICENSE", "LGPL-2.1 with Commons Clause");
    write_file(root, "python/lang/eval.yaml", "rules:\n  - id: py-eval\n");
    write_file(root, "java/spring/csrf.yml", "rules:\n  - id: csrf\n");
    write_file(root, "README.md", "documentation");
    write_file(root, "python/lang/eval.py", "eval(x)");
    write_file(root, ".git/config", "[core]");
    write_file(root, ".git/hooks/pre.yaml", "not a rule");

    let entries = read_entries_from_dir(root).expect("read should succeed");
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();

    assert_eq!(paths, vec!["LICENSE", "java/spring/csrf.yml", "python/lang/eval.yaml"]);
}

#[test]
fn the_licence_is_the_root_one() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    write_file(root, "vendored/LICENSE", "somebody else's terms");
    write_file(root, "LICENSE.md", "the catalogue's terms");

    let entries = read_entries_from_dir(root).unwrap();
    assert_eq!(licence_of(&entries).unwrap(), "the catalogue's terms");
}

#[test]
fn no_licence_is_a_refusal() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    write_file(root, "python/lang/eval.yaml", "rules:\n  - id: py-eval\n");
    write_file(root, "vendored/LICENSE", "not the catalogue's");

    let entries = read_entries_from_dir(root).unwrap();
    let err = licence_of(&entries).expect_err("missing root licence must be refused");
    assert!(err.0.contains("No LICENSE file at the root"));
}

#[test]
fn a_link_is_never_followed() {
    let checkout = tempfile::tempdir().unwrap();
    let host = tempfile::tempdir().unwrap();

    let secret = host.path().join("encryption_key");
    fs::write(&secret, "the host's own secret").unwrap();

    let host_rules = host.path().join("rules");
    write_file(&host_rules, "stolen.yaml", "rules:\n  - id: stolen\n");

    // Create committed symbolic links in checkout pointing outside
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(&secret, checkout.path().join("LICENSE")).unwrap();
        fs::create_dir_all(checkout.path().join("python")).unwrap();
        symlink(host_rules.join("stolen.yaml"), checkout.path().join("python/linked.yaml")).unwrap();
        symlink(&host_rules, checkout.path().join("linked-directory")).unwrap();
    }

    write_file(checkout.path(), "python/lang/eval.yaml", "rules:\n  - id: py-eval\n");

    let entries = read_entries_from_dir(checkout.path()).unwrap();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();

    // Symlinks must not be followed
    assert_eq!(paths, vec!["python/lang/eval.yaml"]);
    for e in &entries {
        assert!(!e.content.contains("host"));
    }

    // Since symlinked LICENSE was ignored, licence_of must fail
    assert!(licence_of(&entries).is_err());
}

#[test]
fn filters_gitleaks_duplicates() {
    let entry_dup = Entry {
        path: "generic/secrets/gitleaks/detected-generic-api-key.yaml".to_owned(),
        content: "rules:\n  - id: generic-api-key\n".to_owned(),
    };
    assert!(is_gitleaks_duplicate(&entry_dup));

    let entry_sec_dup = Entry {
        path: "generic/secrets/security/detected-stripe-api-key.yaml".to_owned(),
        content: "rules:\n  - id: stripe-key\n".to_owned(),
    };
    assert!(is_gitleaks_duplicate(&entry_sec_dup));

    let entry_clean =
        Entry { path: "python/security/eval.yaml".to_owned(), content: "rules:\n  - id: py-eval\n".to_owned() };
    assert!(!is_gitleaks_duplicate(&entry_clean));
}

#[test]
fn test_fixture_files_are_not_rules() {
    let fixture =
        Entry { path: "python/security/eval.test.yaml".to_owned(), content: "rules:\n  - id: py-eval\n".to_owned() };
    assert!(!is_rule(&fixture));

    let rule = Entry { path: "python/security/eval.yaml".to_owned(), content: "rules:\n  - id: py-eval\n".to_owned() };
    assert!(is_rule(&rule));
}

#[test]
fn require_commit_enforces_full_sha() {
    assert!(require_commit("4b825dc642cb6eb9a060e54bf8d69288fbee4904").is_ok());
    assert!(require_commit("4b825dc642cb").is_err()); // short
    assert!(require_commit("main").is_err()); // branch name
    assert!(require_commit("4b825dc642cb6eb9a060e54bf8d69288fbee490z").is_err()); // non-hex
}

#[test]
fn require_allowed_refuses_forbidden_upstreams() {
    assert!(require_allowed(UPSTREAM).is_ok());
    assert!(require_allowed("semgrep/semgrep-rules").is_err());
}

#[test]
fn describe_and_select_respects_languages_and_duplicates() {
    let entries = vec![
        Entry {
            path: "python/lang/eval.yaml".to_owned(),
            content: "rules:\n  - id: py-eval\n    metadata:\n      owasp:\n        - A03:2021\n".to_owned(),
        },
        Entry { path: "java/injection/sql.yaml".to_owned(), content: "rules:\n  - id: sql-injection\n".to_owned() },
        Entry {
            path: "generic/secrets/gitleaks/detected-generic-api-key.yaml".to_owned(),
            content: "rules:\n  - id: gitleaks-key\n".to_owned(),
        },
    ];

    let contents = describe(entries, LICENCE.to_owned());
    assert!(contents.languages.contains_key("python"));
    assert!(contents.languages.contains_key("java"));
    assert!(contents.languages.contains_key("generic"));
    assert!(contents.categories.contains_key("A03"));

    // Select python only
    let langs = BTreeSet::from(["python".to_owned()]);
    let selected = select(&contents, &langs, false).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].name.as_deref(), Some("python/lang/eval.yaml"));

    // Select generic without duplicates: fails because all generic rules are gitleaks duplicates!
    let generic_langs = BTreeSet::from(["generic".to_owned()]);
    let sel_without = select(&contents, &generic_langs, false);
    assert!(sel_without.is_err());
    assert!(sel_without.unwrap_err().0.contains("duplicate gitleaks"));

    // Select generic with duplicates: succeeds
    let sel_with = select(&contents, &generic_langs, true).unwrap();
    assert_eq!(sel_with.len(), 1);
}

#[test]
fn name_for_generates_standard_format() {
    let commit = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
    let langs = BTreeSet::from(["java".to_owned(), "python".to_owned()]);

    let normal = name_for(commit, &langs, false);
    assert_eq!(normal, "opengrep/opengrep-rules@4b825dc642cb (java, python)");

    let with_dups = name_for(commit, &langs, true);
    assert_eq!(with_dups, "opengrep/opengrep-rules@4b825dc642cb (java, python) with gitleaks duplicates");
}

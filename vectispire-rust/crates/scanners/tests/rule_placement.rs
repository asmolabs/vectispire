//! The rules placed into a workspace — `RulePlacementTest` and `BundledRulesTest`'s ground, against
//! this side. The sentences are the Java side's, word for word: the step's failure carries them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::Cell;
use std::path::Path;
use std::time::{Duration, SystemTime};
use vectispire_scanners::rules::{self, RulePlacement, RulesError, StoredFile};

fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, content) in files {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    dir
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn the_embedded_rules_are_the_jars_byte_for_byte() {
    let listed = vectispire_testkit::read("sast/bundled-rules.list");
    let names: Vec<&str> = rules::BUNDLED.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, listed.lines().collect::<Vec<_>>(), "BundledRules.expected() and BUNDLED name the same files");
    for (name, content) in rules::BUNDLED {
        let jar = vectispire_testkit::read(&format!("sast/bundled-rules/{name}"));
        assert_eq!(*content, jar.as_bytes(), "{name}");
    }
}

#[test]
fn the_bundled_tree_is_copied_and_the_secrets_configuration_is_there() {
    let bundled = tempfile::tempdir().unwrap();
    rules::materialise_into(bundled.path()).unwrap();
    let workspace_rules = tempfile::tempdir().unwrap();
    RulePlacement::new(bundled.path()).place_bundled(workspace_rules.path()).unwrap();
    let gitleaks = vectispire_testkit::read("sast/bundled-rules/gitleaks/gitleaks.toml");
    assert_eq!(read(&workspace_rules.path().join("gitleaks/gitleaks.toml")), gitleaks);
    assert!(
        read(&workspace_rules.path().join("semgrep/python/dangerous-eval.yaml"))
            .contains("vectispire.python.eval-on-input")
    );
}

#[test]
fn operator_rules_go_beside_the_bundled_ones_and_overwrite_none() {
    let bundled = tree(&[("semgrep/a.yaml", "bundled")]);
    let operator = tree(&[("a.yaml", "operator"), ("nested/b.yaml", "nested")]);
    let workspace_rules = tempfile::tempdir().unwrap();
    let placement = RulePlacement::new(bundled.path());
    placement.place_bundled(workspace_rules.path()).unwrap();
    let placed = placement
        .place_operator_rules(workspace_rules.path(), Some(&format!(" {} ", operator.path().display())))
        .unwrap();
    assert!(placed);
    assert_eq!(read(&workspace_rules.path().join("semgrep/a.yaml")), "bundled");
    assert_eq!(read(&workspace_rules.path().join("semgrep/operator/a.yaml")), "operator");
    assert_eq!(read(&workspace_rules.path().join("semgrep/operator/nested/b.yaml")), "nested");
}

#[test]
fn a_link_to_a_directory_is_placed_as_a_directory_and_never_followed() {
    // `Files.walk` does not follow links: the Java copy makes the directory and copies nothing of
    // what it points at — an operator volume cannot drag a host tree into every workspace.
    let elsewhere = tree(&[("outside.yaml", "not the operator's")]);
    let operator = tree(&[("a.yaml", "operator")]);
    std::os::unix::fs::symlink(elsewhere.path(), operator.path().join("linked")).unwrap();
    let workspace_rules = tempfile::tempdir().unwrap();
    RulePlacement::new(tempfile::tempdir().unwrap().path())
        .place_operator_rules(workspace_rules.path(), Some(&operator.path().display().to_string()))
        .unwrap();
    let linked = workspace_rules.path().join("semgrep/operator/linked");
    assert!(linked.is_dir() && !linked.is_symlink());
    assert!(!linked.join("outside.yaml").exists(), "the link was followed");
}

#[test]
fn no_operator_directory_configured_places_nothing() {
    let placement = RulePlacement::new(tempfile::tempdir().unwrap().path());
    let workspace_rules = tempfile::tempdir().unwrap();
    assert!(!placement.place_operator_rules(workspace_rules.path(), None).unwrap());
    assert!(!placement.place_operator_rules(workspace_rules.path(), Some(" \t")).unwrap());
}

#[test]
fn an_unreadable_operator_directory_fails_rather_than_scanning_with_the_bundled_rules_alone() {
    let placement = RulePlacement::new(tempfile::tempdir().unwrap().path());
    let workspace_rules = tempfile::tempdir().unwrap();
    let missing = placement.place_operator_rules(workspace_rules.path(), Some("/nowhere/at/all")).unwrap_err();
    assert_eq!(missing.to_string(), "VECTISPIRE_SEMGREP_RULES_DIR points at /nowhere/at/all, which cannot be read.");
    let file = tree(&[("rules.yaml", "x")]);
    let path = file.path().join("rules.yaml").display().to_string();
    let not_a_directory = placement.place_operator_rules(workspace_rules.path(), Some(&path)).unwrap_err();
    assert_eq!(
        not_a_directory.to_string(),
        format!("VECTISPIRE_SEMGREP_RULES_DIR points at {path}, which is not a directory.")
    );
    assert!(matches!(not_a_directory, RulesError::OperatorRulesUnavailable(_)));
}

#[test]
fn an_uploaded_rule_set_replaces_the_environment_directory_and_is_written_by_basename() {
    let placement = RulePlacement::new(tempfile::tempdir().unwrap().path());
    let environment = tree(&[("env.yaml", "from the environment")]);
    let workspace_rules = tempfile::tempdir().unwrap();
    let asked = Cell::new(None);
    let provider = |hash: &str| {
        asked.set(Some(hash.to_owned()));
        Ok(vec![StoredFile {
            path: "../../escape/rule-0001.yaml".into(),
            original_name: "mine.yaml".into(),
            content: "uploaded".into(),
        }])
    };
    let placed = placement
        .place_rule_set(
            workspace_rules.path(),
            Some("abc123"),
            Some(&provider),
            Some(&environment.path().display().to_string()),
        )
        .unwrap();
    assert!(placed);
    assert_eq!(asked.take().as_deref(), Some("abc123"));
    assert_eq!(read(&workspace_rules.path().join("semgrep/operator/rule-0001.yaml")), "uploaded");
    assert!(!workspace_rules.path().join("semgrep/operator/env.yaml").exists(), "replaced, not merged");
    assert!(!workspace_rules.path().join("escape").exists());
}

#[test]
fn with_no_rule_set_named_the_environment_directory_applies() {
    let placement = RulePlacement::new(tempfile::tempdir().unwrap().path());
    let environment = tree(&[("env.yaml", "from the environment")]);
    let workspace_rules = tempfile::tempdir().unwrap();
    for hash in [None, Some(""), Some("  ")] {
        assert!(
            placement
                .place_rule_set(workspace_rules.path(), hash, None, Some(&environment.path().display().to_string()))
                .unwrap()
        );
    }
    assert_eq!(read(&workspace_rules.path().join("semgrep/operator/env.yaml")), "from the environment");
}

#[test]
fn a_rule_set_the_executor_cannot_have_fails_with_the_java_sentences() {
    let placement = RulePlacement::new(tempfile::tempdir().unwrap().path());
    let rules = tempfile::tempdir().unwrap();
    let no_provider = placement.place_rule_set(rules.path(), Some("h1"), None, None).unwrap_err();
    assert_eq!(
        no_provider.to_string(),
        "This scan requires uploaded rule set h1, and this executor has no way to fetch it."
    );
    let refusing = |_: &str| Err("503 from the control plane".to_owned());
    let refused = placement.place_rule_set(rules.path(), Some("h2"), Some(&refusing), None).unwrap_err();
    assert_eq!(refused.to_string(), "Rule set h2 could not be fetched: 503 from the control plane");
    let empty = |_: &str| Ok(Vec::new());
    let came_back_empty = placement.place_rule_set(rules.path(), Some("h3"), Some(&empty), None).unwrap_err();
    assert_eq!(
        came_back_empty.to_string(),
        "Rule set h3 came back empty; refusing to scan with the bundled rules alone."
    );
    let hostile =
        |_: &str| Ok(vec![StoredFile { path: "a/..".into(), original_name: String::new(), content: "x".into() }]);
    let unwritable = placement.place_rule_set(rules.path(), Some("h4"), Some(&hostile), None).unwrap_err();
    assert!(
        unwritable.to_string().starts_with("Rule set h4 could not be written into the workspace: "),
        "{unwritable}"
    );
}

#[test]
fn the_materialised_rules_go_with_their_owner() {
    let materialised = rules::materialise().unwrap();
    let directory = materialised.tree().parent().unwrap().to_owned();
    assert!(materialised.tree().join("gitleaks/gitleaks.toml").is_file());
    assert!(directory.join(rules::IN_USE).is_file(), "the lock beside the tree, never in it");
    drop(materialised);
    assert!(!directory.exists());
}

#[test]
fn the_sweep_removes_abandoned_directories_and_spares_locked_ones_links_and_strangers() {
    let parent = tempfile::tempdir().unwrap();
    let keep = parent.path().join(format!("{}keep", rules::PREFIX));
    std::fs::create_dir(&keep).unwrap();
    let abandoned = parent.path().join(format!("{}old", rules::PREFIX));
    std::fs::create_dir_all(abandoned.join(rules::TREE)).unwrap();
    std::fs::write(abandoned.join(rules::IN_USE), "").unwrap();
    let pre_lock = parent.path().join(format!("{}prelock", rules::PREFIX));
    std::fs::create_dir(&pre_lock).unwrap();
    let locked = parent.path().join(format!("{}live", rules::PREFIX));
    std::fs::create_dir(&locked).unwrap();
    let lock = std::fs::File::create(locked.join(rules::IN_USE)).unwrap();
    lock.lock().unwrap();
    let stranger = parent.path().join("someone-else");
    std::fs::create_dir(&stranger).unwrap();
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("precious"), "x").unwrap();
    let link = parent.path().join(format!("{}link", rules::PREFIX));
    std::os::unix::fs::symlink(target.path(), &link).unwrap();

    rules::sweep(parent.path(), SystemTime::now() + Duration::from_secs(60), &keep);

    assert!(!abandoned.exists(), "an unlocked leftover goes");
    assert!(!pre_lock.exists(), "a leftover from before the lock goes");
    assert!(locked.exists(), "a directory another process holds stays");
    assert!(keep.exists() && stranger.exists());
    assert!(target.path().join("precious").exists(), "a link is never followed");
    drop(lock);
}

#[test]
fn the_sweep_spares_what_was_written_after_this_process_started() {
    let parent = tempfile::tempdir().unwrap();
    let keep = parent.path().join(format!("{}keep", rules::PREFIX));
    std::fs::create_dir(&keep).unwrap();
    let recent = parent.path().join(format!("{}recent", rules::PREFIX));
    std::fs::create_dir(&recent).unwrap();
    rules::sweep(parent.path(), SystemTime::now() - Duration::from_secs(3600), &keep);
    assert!(recent.exists());
}

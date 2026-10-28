//! The property table against the Java source it was written from — so that a name or a default changed
//! there is red here, rather than a deployment that sets the variable it always set and finds it ignored.
//!
//! Three things are read, not remembered: `application.yaml` (every placeholder chain and default), the
//! `@Value("${key:default}")` expressions in the Java sources, and — in the other direction — that every
//! property the table declares is one the loader reads.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use vectispire_cp_runtime::property::{Environment, PROPERTIES, Source};
use vectispire_cp_runtime::settings::Settings;

fn java() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../vectispire-java")
}

/// `key -> (variables in the order tried, default)` for every placeholder `application.yaml` holds.
fn yaml_placeholders() -> BTreeMap<String, (Vec<String>, String)> {
    let text = std::fs::read_to_string(java().join("vectispire-core/src/main/resources/application.yaml")).unwrap();
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut found = BTreeMap::new();
    for line in text.lines() {
        let content = line.trim();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let (key, value) = match content.split_once(": ") {
            Some((key, value)) => (key, value.trim()),
            None => (content.trim_end_matches(':'), ""),
        };
        while stack.last().is_some_and(|(at, _)| *at >= indent) {
            stack.pop();
        }
        if value.is_empty() {
            stack.push((indent, key.to_owned()));
            continue;
        }
        let full = stack.iter().map(|(_, k)| k.as_str()).chain([key]).collect::<Vec<_>>().join(".");
        if let Some((names, default)) = placeholder(value) {
            found.insert(full, (names, default));
        }
    }
    found
}

/// `${A:${B:default}}` as `([A, B], "default")`; a reference to another property (`${spring.application.name}`) is not a variable.
fn placeholder(value: &str) -> Option<(Vec<String>, String)> {
    let mut names = Vec::new();
    let mut rest = value;
    loop {
        let inner = rest.strip_prefix("${")?.strip_suffix('}')?;
        let (name, tail) = inner.split_once(':')?;
        if name.contains('.') {
            return None;
        }
        names.push(name.to_owned());
        if tail.starts_with("${") {
            rest = tail;
        } else {
            return Some((names, tail.to_owned()));
        }
    }
}

fn java_sources() -> String {
    fn walk(directory: &Path, into: &mut String) {
        for entry in std::fs::read_dir(directory).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, into);
            } else if path.extension().is_some_and(|extension| extension == "java") {
                into.push_str(&std::fs::read_to_string(&path).unwrap());
            }
        }
    }
    let mut all = String::new();
    for module in ["vectispire-core", "vectispire-common"] {
        walk(&java().join(module).join("src/main/java"), &mut all);
    }
    all
}

#[test]
fn every_placeholder_of_application_yaml_is_in_the_table_with_its_names_and_its_default() {
    let yaml = yaml_placeholders();
    assert!(yaml.len() > 50, "the parser read {} placeholders — it is not reading the file", yaml.len());
    for (key, (names, default)) in &yaml {
        let property = PROPERTIES
            .iter()
            .find(|property| property.key == key)
            .unwrap_or_else(|| panic!("{key} is in application.yaml and not in the table"));
        assert_eq!(property.source, Source::Yaml, "{key}");
        assert_eq!(
            property.names,
            names.iter().map(String::as_str).collect::<Vec<_>>(),
            "{key}: the variables tried, in order"
        );
        assert_eq!(property.default, Some(default.as_str()), "{key}: the default");
    }
}

#[test]
fn every_yaml_property_of_the_table_is_still_in_application_yaml() {
    let yaml = yaml_placeholders();
    for property in PROPERTIES.iter().filter(|property| property.source == Source::Yaml) {
        assert!(
            yaml.contains_key(property.key),
            "{} is in the table as an application.yaml property and the file no longer has it",
            property.key
        );
    }
}

#[test]
fn every_value_expression_of_the_table_is_in_the_java_sources() {
    let sources = java_sources();
    for property in PROPERTIES.iter().filter(|property| property.source == Source::Value) {
        let expected = match (property.default, property.key) {
            (Some(default), key) => format!("${{{key}:{default}}}"),
            (None, "vectispire.reports.lease") => "${vectispire.reports.lease:#{null}}".to_owned(),
            (None, key) => format!("${{{key}}}"),
        };
        assert!(sources.contains(&expected), "{expected} is not in the Java sources");
    }
}

#[test]
fn the_names_are_unique() {
    let mut keys = BTreeSet::new();
    for property in PROPERTIES {
        assert!(keys.insert(property.key), "{} twice", property.key);
    }
}

#[test]
fn the_loader_reads_every_property_the_table_declares() {
    // Nothing set: the conditional groups — a provider, a mail relay — are not read, and nothing else is missed.
    let (_, report) = Settings::load(&Environment::of([], [])).unwrap();
    let read: BTreeSet<&str> = report.iter().map(|line| line.key).collect();
    let unread: BTreeSet<&str> =
        PROPERTIES.iter().map(|property| property.key).filter(|key| !read.contains(key)).collect();
    let conditional: BTreeSet<&str> = [
        "vectispire.oidc.client-id",
        "vectispire.oidc.client-secret",
        "vectispire.oidc.name",
        "vectispire.mail.port",
        "vectispire.mail.username",
        "vectispire.mail.password",
        "vectispire.mail.starttls",
    ]
    .into_iter()
    .collect();
    assert_eq!(unread, conditional);

    // And with the groups switched on, every one is.
    let on = Environment::of(
        [
            ("VECTISPIRE_OIDC_ISSUER", "https://sso.example.org"),
            ("VECTISPIRE_OIDC_CLIENT_ID", "vectispire"),
            ("VECTISPIRE_MAIL_HOST", "smtp.example.org"),
        ],
        [],
    );
    let (_, report) = Settings::load(&on).unwrap();
    let read: BTreeSet<&str> = report.iter().map(|line| line.key).collect();
    for property in PROPERTIES {
        assert!(read.contains(property.key), "{} is declared and never read", property.key);
    }
}

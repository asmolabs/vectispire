//! The census, the project manifest and the API discovery against the Java side's answers for every tree of
//! `reference/workspace/cases/` — built here as `WorkspaceReferenceSetTest` builds them, and answered byte for
//! byte as the agent's mapper writes the records.
//!
//! The trees are the repository author's choices: links out of the tree to a manifest, a specification and
//! controllers that must never be read, files past the size bound, two hundred levels of directories, bytes that
//! are not UTF-8, manifests that do not parse, shapes written against the patterns.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;

use base64::Engine;
use serde_json::{Map, Value, json};
use vectispire_domain::java;
use vectispire_domain::language::Language;
use vectispire_scanners::{api_discovery, census, manifest};

/// What a link may point at, beside the tree — `WorkspaceReferenceSetTest.outside`, file for file.
fn outside(outside: &Path) {
    std::fs::create_dir_all(outside.join("dir")).unwrap();
    for (name, content) in [
        ("package.json", "{\"version\":\"host-secret\"}"),
        ("pom.xml", "<project><version>host-secret</version></project>"),
        ("gradle.properties", "version=host-secret\n"),
        ("pyproject.toml", "[project]\nversion = \"host-secret\"\n"),
        (
            "openapi.json",
            "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"host\"},\"paths\":{\"/host-spec\":{\"get\":{}}}}",
        ),
        ("Host.java", "@RestController\nclass Host {\n  @GetMapping(\"/host-java\")\n  void get() {}\n}\n"),
        ("ingress.yaml", "kind: Ingress\nspec:\n  - path: /\n"),
        ("dir/app.py", "@app.get(\"/host-dir\")\ndef host(): pass\n"),
        ("dir/Main.java", "class Main {}\n"),
    ] {
        std::fs::write(outside.join(name), content).unwrap();
    }
}

fn build(tree: &Path, outside: &Path, entry: &Value) {
    let path = tree.join(entry["path"].as_str().unwrap());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    if entry["dir"].as_bool().unwrap_or(false) {
        std::fs::create_dir_all(&path).unwrap();
    } else if let Some(target) = entry["link"].as_str() {
        std::os::unix::fs::symlink(target.replace("{outside}", &outside.display().to_string()), &path).unwrap();
    } else if let Some(encoded) = entry["base64"].as_str() {
        std::fs::write(&path, base64::engine::general_purpose::STANDARD.decode(encoded).unwrap()).unwrap();
    } else {
        let repeat = usize::try_from(entry["repeat"].as_u64().unwrap_or(1)).unwrap();
        let mut content = entry["head"].as_str().unwrap_or("").to_owned();
        content.push_str(&entry["text"].as_str().unwrap_or("").repeat(repeat));
        content.push_str(entry["tail"].as_str().unwrap_or(""));
        std::fs::write(&path, content).unwrap();
    }
}

fn census_of(census: &census::Census) -> Value {
    json!({"found": census.found.iter().map(|language| language.wire_name()).collect::<Vec<_>>(), "complete": census.complete})
}

fn answer(spec: &Value, place: &Path) -> String {
    let outside_dir = place.join("outside");
    outside(&outside_dir);
    let tree = place.join("tree");
    std::fs::create_dir(&tree).unwrap();
    for entry in spec["entries"].as_array().unwrap() {
        build(&tree, &outside_dir, entry);
    }
    let root = spec["root"].as_str().map_or_else(|| tree.clone(), |root| tree.join(root));

    let mut answer = Map::new();
    answer.insert("name".into(), spec["name"].clone());
    answer.insert("census".into(), census_of(&census::of(&root, &BTreeSet::new())));
    if let Some(wanted) = spec["wanted"].as_array() {
        let wanted: BTreeSet<Language> =
            wanted.iter().map(|name| Language::from_wire_name(name.as_str().unwrap()).unwrap()).collect();
        answer.insert("censusWanted".into(), census_of(&census::of(&root, &wanted)));
    }
    let project = manifest::read(&root).map(|project| json!({"type": project.kind, "version": project.version}));
    answer.insert("project".into(), project.unwrap_or(Value::Null));
    let ceiling =
        spec["ceiling"].as_u64().map_or(api_discovery::MAX_PER_REPOSITORY, |ceiling| usize::try_from(ceiling).unwrap());
    let api = match api_discovery::scan_bounded(&root, api_discovery::DEADLINE, &mut std::time::Instant::now, ceiling) {
        Ok(mut discovery) => {
            discovery.endpoints.sort_by(|a, b| java::compare_utf16(&a.file_path, &b.file_path));
            discovery.contracts.sort_by(|a, b| java::compare_utf16(&a.contract_path, &b.contract_path));
            json!({"endpoints": discovery.endpoints, "contracts": discovery.contracts})
        }
        Err(failed) => json!({"failure": failed.0.replace(&root.display().to_string(), "{root}")}),
    };
    answer.insert("api".into(), api);
    serde_json::to_string(&answer).unwrap()
}

#[test]
fn every_tree_gives_the_java_answers_byte_for_byte() {
    let cases = vectispire_testkit::reference_root().join("workspace/cases");
    let mut topics: Vec<_> = std::fs::read_dir(&cases)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".json"))
        .collect();
    topics.sort();
    assert!(topics.len() >= 5, "the reference set is there: {topics:?}");
    let temporary = tempfile::tempdir().unwrap();
    let mut index = 0;
    let mut differences = Vec::new();
    let mut compared = 0;
    for topic in &topics {
        let specs = vectispire_testkit::read_json(&format!("workspace/cases/{topic}"));
        let java = vectispire_testkit::read(&format!("workspace/answers/{}", topic.replace(".json", ".jsonl")));
        let mut java_lines = java.lines();
        for spec in specs["cases"].as_array().unwrap() {
            let place = temporary.path().join(format!("case-{index}"));
            index += 1;
            std::fs::create_dir(&place).unwrap();
            let ours = answer(spec, &place);
            let theirs = java_lines.next().unwrap_or_default();
            compared += 1;
            if ours != theirs {
                differences.push(format!(
                    "{topic} {}\n  java: {}\n  rust: {}",
                    spec["name"],
                    clip(theirs),
                    clip(&ours)
                ));
            }
        }
        assert!(java_lines.next().is_none(), "{topic}: the Java answers have more lines than there are cases");
    }
    assert!(compared >= 150, "{compared} cases compared");
    assert!(differences.is_empty(), "{} of {compared} differ:\n{}", differences.len(), differences.join("\n"));
}

/// A long answer, cut at a character boundary for the report.
fn clip(text: &str) -> String {
    if text.len() <= 3000 { text.to_owned() } else { format!("{}…", text.chars().take(3000).collect::<String>()) }
}

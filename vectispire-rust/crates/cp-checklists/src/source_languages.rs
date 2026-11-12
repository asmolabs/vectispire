//! `SourceLanguages`: which languages a static analysis must read for a checklist to call a repository examined —
//! those a program's behaviour is written in. `json` and `yaml` are data, `html` markup, `dockerfile` and
//! `terraform` infrastructure the IaC step reads; `bash` is kept, since a shell script runs in the pipelines and on
//! the hosts.
//!
//! Java decides it with an exhaustive `switch`, so a language added to the vocabulary does not compile until somebody
//! decides its side. Here the two lists are written out and a test requires every language in exactly one of them.

use std::collections::BTreeSet;

use vectispire_domain::language::Language;

/// The source languages, by wire name.
const SOURCE: [&str; 19] = [
    "apex",
    "bash",
    "c",
    "clojure",
    "csharp",
    "elixir",
    "go",
    "java",
    "javascript",
    "kotlin",
    "ocaml",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "solidity",
    "swift",
    "typescript",
];

pub fn is_source(language: Language) -> bool {
    SOURCE.contains(&language.wire_name())
}

/// The source languages among these, in the vocabulary's order.
pub fn of(languages: &BTreeSet<Language>) -> BTreeSet<Language> {
    languages.iter().copied().filter(|language| is_source(*language)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The languages that are not source, by wire name.
    const NOT_SOURCE: [&str; 5] = ["json", "yaml", "html", "dockerfile", "terraform"];

    #[test]
    fn every_language_is_decided_once() {
        for language in Language::all() {
            let name = language.wire_name();
            assert!(SOURCE.contains(&name) != NOT_SOURCE.contains(&name), "{name} is on exactly one side");
        }
        assert_eq!(SOURCE.len() + NOT_SOURCE.len(), Language::all().count());
    }
}

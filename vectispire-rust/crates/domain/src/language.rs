//! `Language`: what a census counts in a tree, what a SAST rule set reads and what a plugin manifest declares — one
//! vocabulary, in the enum's order, which is the order a set of them is written in.

use crate::java;

/// The wire names, in the enum's order.
pub const LANGUAGES: [&str; 24] = [
    "apex",
    "bash",
    "c",
    "clojure",
    "csharp",
    "dockerfile",
    "elixir",
    "go",
    "html",
    "java",
    "javascript",
    "json",
    "kotlin",
    "ocaml",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "solidity",
    "swift",
    "terraform",
    "typescript",
    "yaml",
];

/// One language, ordered as the enum orders it — a `BTreeSet<Language>` is Java's `EnumSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Language(u8);

impl Language {
    /// Every language, in the enum's order.
    pub fn all() -> impl Iterator<Item = Language> {
        (0..LANGUAGES.len()).filter_map(|index| u8::try_from(index).ok()).map(Language)
    }

    pub fn wire_name(self) -> &'static str {
        LANGUAGES.get(usize::from(self.0)).copied().unwrap_or("")
    }

    /// `Language.fromWireName`: trimmed as `String.trim` trims, lowered under `Locale.ROOT`, one of the wire names.
    pub fn from_wire_name(value: &str) -> Option<Language> {
        let normalized = java::to_lower_root(java::trim(value));
        Language::all().find(|language| language.wire_name() == normalized)
    }
}

/// `Language`'s extensions, in the enum's order: what follows a name's last dot names these languages.
const EXTENSIONS: [(&str, &[&str]); 24] = [
    ("apex", &["cls", "trigger"]),
    ("bash", &["sh", "bash"]),
    ("c", &["c", "h"]),
    ("clojure", &["clj", "cljs", "cljc"]),
    ("csharp", &["cs", "csx", "csproj", "sln"]),
    ("dockerfile", &["dockerfile"]),
    ("elixir", &["ex", "exs"]),
    ("go", &["go"]),
    ("html", &["html", "htm"]),
    ("java", &["java"]),
    ("javascript", &["js", "jsx", "mjs", "cjs"]),
    ("json", &["json"]),
    ("kotlin", &["kt", "kts"]),
    ("ocaml", &["ml", "mli"]),
    ("php", &["php"]),
    ("python", &["py", "pyi"]),
    ("ruby", &["rb"]),
    ("rust", &["rs"]),
    ("scala", &["scala", "sc"]),
    ("solidity", &["sol"]),
    ("swift", &["swift"]),
    ("terraform", &["tf", "tfvars", "hcl"]),
    ("typescript", &["ts", "tsx", "mts", "cts"]),
    ("yaml", &["yaml", "yml"]),
];

/// `Language`'s whole file names — a manifest is a sign too: `pom.xml` says Java before any `.java` is seen.
const FILE_NAMES: [(&str, &[&str]); 24] = [
    ("apex", &[]),
    ("bash", &[]),
    ("c", &[]),
    ("clojure", &["project.clj", "deps.edn"]),
    ("csharp", &[]),
    ("dockerfile", &["dockerfile", "containerfile"]),
    ("elixir", &["mix.exs"]),
    ("go", &["go.mod"]),
    ("html", &[]),
    ("java", &["pom.xml", "build.gradle", "build.gradle.kts"]),
    ("javascript", &["package.json"]),
    ("json", &[]),
    ("kotlin", &[]),
    ("ocaml", &["dune-project"]),
    ("php", &["composer.json"]),
    ("python", &["pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "pipfile"]),
    ("ruby", &["gemfile"]),
    ("rust", &["cargo.toml"]),
    ("scala", &["build.sbt"]),
    ("solidity", &[]),
    ("swift", &["package.swift"]),
    ("terraform", &[]),
    ("typescript", &["tsconfig.json"]),
    ("yaml", &[]),
];

impl Language {
    /// `Language.ofFileName`: the languages a file's name says it belongs to — empty for a name that says nothing.
    ///
    /// By name alone, lowered as `Locale.ROOT` lowers it: the whole name against the manifests, what follows the
    /// last dot (when something does) against the extensions, and `Dockerfile.<anything>`. No pattern and no file
    /// opened — the census runs over a tree somebody else wrote.
    pub fn of_file_name(file_name: &str) -> std::collections::BTreeSet<Language> {
        let mut found = std::collections::BTreeSet::new();
        if file_name.is_empty() {
            return found;
        }
        let lower = java::to_lower_root(file_name);
        let extension =
            lower.rfind('.').and_then(|dot| lower.get(dot.saturating_add(1)..)).filter(|ext| !ext.is_empty());
        for language in Language::all() {
            let named =
                FILE_NAMES.iter().any(|(wire, names)| *wire == language.wire_name() && names.contains(&lower.as_str()));
            let extended = extension.is_some_and(|ext| {
                EXTENSIONS.iter().any(|(wire, extensions)| *wire == language.wire_name() && extensions.contains(&ext))
            });
            if named || extended || (language.wire_name() == "dockerfile" && lower.starts_with("dockerfile.")) {
                found.insert(language);
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(file_name: &str) -> Vec<&'static str> {
        Language::of_file_name(file_name).into_iter().map(Language::wire_name).collect()
    }

    #[test]
    fn a_file_name_names_its_languages_as_java_names_them() {
        assert_eq!(names("App.JAVA"), ["java"]);
        assert_eq!(names("build.gradle.kts"), ["java", "kotlin"]);
        assert_eq!(names("Dockerfile.prod"), ["dockerfile"]);
        assert_eq!(names("dockerfile."), ["dockerfile"], "the prefix rule, with nothing after the dot");
        assert_eq!(names("Containerfile"), ["dockerfile"]);
        assert_eq!(names("tsconfig.json"), ["json", "typescript"]);
        assert!(names("README").is_empty());
        assert!(names("noext.").is_empty(), "a trailing dot names no extension");
        assert!(names(".").is_empty());
        assert!(names("").is_empty());
        assert_eq!(names(".py"), ["python"], "a dot first is still an extension");
    }

    #[test]
    fn a_language_is_read_as_java_reads_it_and_ordered_as_the_enum() {
        assert_eq!(Language::from_wire_name(" Java ").map(Language::wire_name), Some("java"));
        assert_eq!(Language::from_wire_name("\u{a0}java"), None, "String.trim keeps a no-break space");
        assert!(Language::from_wire_name("go") < Language::from_wire_name("yaml"));
        assert_eq!(Language::all().count(), LANGUAGES.len());
    }
}

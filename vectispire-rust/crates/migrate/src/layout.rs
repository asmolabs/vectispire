//! Where a migration may live, and what a migration written once may say — a port of
//! `MigrationLayoutTest` (decision 0027), run over the set this crate embeds.
//!
//! **Each rule closes a failure that is silent on at least one engine.** Flyway reads `common` and
//! then the engine's directory, so a version written for MySQL but forgotten for PostgreSQL applies on
//! one engine only; a version in both `common` and a vendor directory fails at startup on that vendor
//! only; a misnamed file is skipped without a word; and a type spelled for one engine in a file every
//! engine runs truncates the audit chain's timestamps on MySQL.
//!
//! The Java test also reads the integration campaign's probe migration; that file is not part of the
//! jar, so it is not embedded here, and the Java test keeps checking it.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use crate::dialect::Engine;
use crate::set::{COMMON, MigrationSet};

/// The last version written before the rule; V1 to V39 stay in every vendor directory forever.
pub const LAST_VERSION_BEFORE_THE_RULE: u64 = 39;

const MIGRATION_NAME: &str = r"^V([1-9][0-9]*)__[a-z0-9_]+\.sql$";

/// Every rule the set breaks, in words a reviewer acts on; empty when the layout is sound.
pub fn check(set: &MigrationSet) -> Vec<String> {
    let mut violations = Vec::new();
    let name = Regex::new(MIGRATION_NAME).unwrap_or_else(|_| unreachable!("a constant pattern"));
    let vendors: BTreeSet<&str> = Engine::ALL.iter().map(|engine| engine.vendor()).collect();
    let version = |file: &str| -> Option<u64> { name.captures(file).and_then(|c| c[1].parse().ok()) };

    // Every directory is an engine Vectispire maps, or common; nothing lies directly under db/migration.
    let mut by_directory: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for file in set.files() {
        if file.directory.is_empty() {
            violations.push(format!("{} is directly under db/migration, on no location Flyway reads", file.name));
            continue;
        }
        by_directory.entry(file.directory.as_str()).or_default().push(file.name.as_str());
    }
    let mut expected: BTreeSet<&str> = vendors.clone();
    expected.insert(COMMON);
    let found: BTreeSet<&str> = by_directory.keys().copied().collect();
    if found != expected {
        violations.push(format!("db/migration holds {found:?}, expected exactly {expected:?}"));
    }

    // Every file is a migration Flyway will read.
    for (directory, files) in &by_directory {
        for file in files {
            if version(file).is_none() && !(*directory == COMMON && *file == "README.md") {
                violations.push(format!(
                    "{directory}/{file}: Flyway skips a file whose name it does not recognise, without a word. Expected \
                     V<version>__<description>.sql"
                ));
            }
        }
    }

    // A version lives in common once, or in every engine's directory — never both, never some.
    let mut by_version: BTreeMap<u64, BTreeMap<&str, Vec<&str>>> = BTreeMap::new();
    for (directory, files) in &by_directory {
        for file in files {
            if let Some(v) = version(file) {
                by_version.entry(v).or_default().entry(directory).or_default().push(file);
            }
        }
    }
    for (v, places) in &by_version {
        for (directory, files) in places {
            if files.len() > 1 {
                violations.push(format!("V{v} appears {} times in {directory}: {files:?}", files.len()));
            }
        }
        if places.contains_key(COMMON) {
            if places.len() > 1 {
                let others: Vec<_> = places.keys().filter(|d| **d != COMMON).collect();
                violations.push(format!(
                    "V{v} is in common and also in {others:?} — Flyway refuses the duplicate on that engine only"
                ));
            }
            continue;
        }
        let missing: Vec<_> = vendors.iter().filter(|vendor| !places.contains_key(**vendor)).collect();
        if !missing.is_empty() {
            violations.push(format!(
                "V{v} is in {:?} but not in {missing:?} — it would apply on some engines and silently not on the others",
                places.keys().collect::<Vec<_>>()
            ));
            continue;
        }
        let names: BTreeSet<&str> = places.values().flatten().copied().collect();
        if names.len() > 1 {
            violations.push(format!("V{v} has a different name per engine: {names:?}"));
        }
    }

    // V1 to V39 stay in the vendor directories, where their checksums were recorded.
    for v in 1..=LAST_VERSION_BEFORE_THE_RULE {
        for vendor in &vendors {
            let present = by_directory.get(vendor).is_some_and(|files| files.iter().any(|file| version(file) == Some(v)));
            if !present {
                violations.push(format!(
                    "V{v} is missing from {vendor}: rewriting an applied migration changes its checksum, and Flyway \
                     then refuses to start every installation that applied it"
                ));
            }
        }
    }

    // A new migration identical on every engine is written once, in common.
    let content = |directory: &str, file: &str| {
        set.files().iter().find(|f| f.directory == directory && f.name == file).map(|f| f.bytes.as_slice())
    };
    if let Some(first) = vendors.iter().next() {
        for file in by_directory.get(first).into_iter().flatten() {
            if version(file).is_none_or(|v| v <= LAST_VERSION_BEFORE_THE_RULE) {
                continue;
            }
            let contents: BTreeSet<Option<&[u8]>> = vendors.iter().map(|vendor| content(vendor, file)).collect();
            if contents.len() == 1 && contents.iter().all(Option::is_some) {
                violations.push(format!("{file} is identical on every engine: it belongs in common"));
            }
        }
    }

    // A common migration names no engine, and only placeholders every engine answers.
    violations.extend(common_names_no_engine(set));
    violations
}

/// A token that belongs to one engine, and what to write instead — the Java test's list, verbatim.
fn engine_tokens() -> Vec<(Regex, &'static str)> {
    [
        (
            r"\bauto_increment\b|\bautoincrement\b|\bgenerated\s+(always|by\s+default)\b|\b(big)?serial\b|\bidentity\b",
            "write `id ${id},`",
        ),
        (
            r"\bdatetime\b|\btimestamptz\b|\btimestamp\b|\bwith\s+time\s+zone\b",
            "write ${ts}: a bare datetime truncates to the second on MySQL",
        ),
        (r"\bbit\s*\(|\bb'[01]'|\bboolean\b|\btinyint\b|\btrue\b|\bfalse\b", "write ${bool}, ${true} and ${false}"),
        (r"\b(long|medium|tiny)text\b|\bclob\b|\btext\b", "write ${text}: MySQL's text stops at 64 KiB"),
        (r"\bdouble\b|\bprecision\b|\breal\b|\bfloat\b", "write ${double}"),
        (
            r"\bbytea\b|\b(long|medium|tiny)?blob\b|\b(var)?binary\b|\boid\b",
            "write ${bytes}: MySQL's blob stops at 64 KiB, and PostgreSQL's large object is not a column",
        ),
        (
            r"\breferences\b",
            "a foreign key diverges: MySQL discards an inline one — write it in both vendor directories, as a named \
             constraint",
        ),
        (
            r"\bmodify\b|\balter\s+column\b|\bchange\s+column\b",
            "a column change diverges (MODIFY, ALTER COLUMN … TYPE, a table rebuild) — write it in both vendor directories",
        ),
        (
            r"\bnow\s*\(|\bcurrent_timestamp\b|\binterval\b|\bdate_(add|sub)\b|\bjulianday\b|\bstrftime\b|\bextract\s*\(",
            "date arithmetic diverges — write it in both vendor directories",
        ),
        (
            r"\bdrop\s+index\b|\bindex\s+if\s+not\s+exists\b",
            "index syntax diverges (MySQL's drop index names the table) — write it in the both vendor directories",
        ),
        (
            r"\bon\s+conflict\b|\bon\s+duplicate\s+key\b|\binsert\s+(ignore|or)\b|\breplace\s+into\b",
            "an upsert diverges — write it in both vendor directories",
        ),
        (r"\bpragma\b|\bengine\s*=|\bunsigned\b|\bjsonb?\b", "engine-specific — write it in both vendor directories"),
        ("`|\"|::|\\$", "quoting, casts and dollar bodies are engine-specific — plain identifiers only"),
    ]
    .into_iter()
    .map(|(pattern, instead)| {
        // ASCII case folding and ASCII word boundaries: every pattern is ASCII, and the crate is built
        // without Unicode case tables.
        let regex = Regex::new(&format!("(?i-u){pattern}")).unwrap_or_else(|_| unreachable!("a constant pattern"));
        (regex, instead)
    })
    .collect()
}

fn common_names_no_engine(set: &MigrationSet) -> Vec<String> {
    let mut violations = Vec::new();
    let known: BTreeSet<&str> = Engine::MySql.placeholders().iter().map(|(name, _)| *name).collect();
    let placeholder = Regex::new(r"\$\{([^}]*)\}").unwrap_or_else(|_| unreachable!("a constant pattern"));
    let id_with_key = Regex::new(r"(?i-u)\$\{id\}\s+primary\s+key").unwrap_or_else(|_| unreachable!("a constant pattern"));
    let block = Regex::new(r"(?s)/\*.*?\*/").unwrap_or_else(|_| unreachable!("a constant pattern"));
    let line = Regex::new(r"--[^\n]*").unwrap_or_else(|_| unreachable!("a constant pattern"));
    let tokens = engine_tokens();

    let commons: Vec<_> = set
        .files()
        .iter()
        .filter(|file| file.directory == COMMON && file.name.ends_with(".sql"))
        .collect();
    if commons.is_empty() {
        violations.push("no common migration was read: the rule would pass having looked at nothing".to_owned());
    }
    for file in commons {
        let sql = String::from_utf8_lossy(&file.bytes);
        let statements = line.replace_all(&block.replace_all(&sql, " "), " ").into_owned();
        for found in placeholder.captures_iter(&statements) {
            if !known.contains(&found[1]) {
                violations.push(format!("common/{}: ${{{}}} is not one of {known:?}", file.name, &found[1]));
            }
        }
        if id_with_key.is_match(&statements) {
            violations.push(format!("common/{}: ${{id}} already carries `primary key` — write `id ${{id}},`", file.name));
        }
        let bare = placeholder.replace_all(&statements, " ");
        for (token, instead) in &tokens {
            if let Some(found) = token.find(&bare) {
                violations.push(format!("common/{}: `{}` — {instead}", file.name, found.as_str()));
            }
        }
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set::File;

    #[test]
    fn the_embedded_layout_is_sound() {
        let violations = check(&MigrationSet::embedded());
        assert!(violations.is_empty(), "{violations:#?}");
    }

    fn with(extra: File) -> Vec<String> {
        let mut files = MigrationSet::embedded().files().to_vec();
        files.push(extra);
        check(&MigrationSet::of(files))
    }

    fn file(directory: &str, name: &str, sql: &str) -> File {
        File { directory: directory.to_owned(), name: name.to_owned(), bytes: sql.as_bytes().to_vec() }
    }

    #[test]
    fn a_version_for_one_engine_only_is_refused() {
        let violations = with(file("mysql", "V9001__only_here.sql", "select 1;"));
        assert!(violations.iter().any(|v| v.contains("V9001 is in") && v.contains("postgresql")), "{violations:?}");
    }

    #[test]
    fn a_version_in_common_and_a_vendor_directory_is_refused() {
        let mut files = MigrationSet::embedded().files().to_vec();
        files.push(file("common", "V9001__twice.sql", "create table t (id ${id});"));
        files.push(file("mysql", "V9001__twice.sql", "create table t (id int);"));
        let violations = check(&MigrationSet::of(files));
        assert!(violations.iter().any(|v| v.contains("V9001 is in common and also in")), "{violations:?}");
    }

    #[test]
    fn a_misnamed_file_and_a_stray_directory_are_refused() {
        assert!(with(file("common", "v9001_x.sql", "")).iter().any(|v| v.contains("Flyway skips a file")));
        assert!(with(file("postgres", "V9001__x.sql", "")).iter().any(|v| v.contains("expected exactly")));
        assert!(with(file("", "V9001__x.sql", "")).iter().any(|v| v.contains("directly under db/migration")));
    }

    #[test]
    fn a_common_migration_naming_an_engine_type_is_refused() {
        let violations = with(file("common", "V9001__typed.sql", "create table t (id ${id}, at datetime);"));
        assert!(violations.iter().any(|v| v.contains("`datetime`")), "{violations:?}");
        let violations = with(file("common", "V9001__unknown.sql", "create table t (x ${nope});"));
        assert!(violations.iter().any(|v| v.contains("${nope} is not one of")), "{violations:?}");
        // A comment may name any engine.
        let fine = with(file("common", "V9001__commented.sql", "-- datetime, not here\ncreate table t (id ${id});"));
        assert!(fine.is_empty(), "{fine:?}");
    }

    #[test]
    fn an_identical_pair_belongs_in_common() {
        let mut files = MigrationSet::embedded().files().to_vec();
        files.push(file("mysql", "V9001__same.sql", "create index i on t (x);"));
        files.push(file("postgresql", "V9001__same.sql", "create index i on t (x);"));
        let violations = check(&MigrationSet::of(files));
        assert!(violations.iter().any(|v| v.contains("belongs in common")), "{violations:?}");
    }
}

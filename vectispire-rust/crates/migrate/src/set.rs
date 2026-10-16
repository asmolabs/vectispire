//! The migration files, and what Flyway resolves from them for one engine.

use std::path::Path;

use crate::checksum;
use crate::dialect::Engine;
use crate::version::Version;
use crate::{Error, embedded};

/// The directory read first on every engine (decision 0027).
pub const COMMON: &str = "common";

/// One file under `db/migration`.
#[derive(Debug, Clone)]
pub struct File {
    /// `common`, an engine's vendor id, any other directory found, or empty for a file directly under
    /// `db/migration`.
    pub directory: String,
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Every file under `db/migration`, as one build of the control plane carries them.
#[derive(Debug, Clone)]
pub struct MigrationSet {
    files: Vec<File>,
}

/// A versioned SQL migration as Flyway resolves it: what is recorded in `flyway_schema_history`.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub version: Version,
    /// The file name with `_` read as spaces, as Flyway's `ResourceNameParser` reads it.
    pub description: String,
    /// The file name, relative to its location — what the `script` column holds.
    pub script: String,
    /// Where it was found: `common` or the engine's directory.
    pub directory: String,
    pub checksum: i32,
    pub sql: String,
}

impl MigrationSet {
    /// The files this crate was built with: `vectispire-core`'s `db/migration`.
    pub fn embedded() -> MigrationSet {
        MigrationSet {
            files: embedded::EMBEDDED
                .iter()
                .map(|(directory, name, bytes)| File {
                    directory: (*directory).to_owned(),
                    name: (*name).to_owned(),
                    bytes: bytes.to_vec(),
                })
                .collect(),
        }
    }

    /// The files under a `db/migration` directory on disk — another commit's, extracted by a test.
    pub fn from_dir(root: &Path) -> std::io::Result<MigrationSet> {
        let mut files = Vec::new();
        let mut entries: Vec<_> = std::fs::read_dir(root)?.collect::<Result<_, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if path.is_dir() {
                let mut inner: Vec<_> = std::fs::read_dir(&path)?.collect::<Result<_, _>>()?;
                inner.sort_by_key(std::fs::DirEntry::file_name);
                for file in inner.into_iter().filter(|file| file.path().is_file()) {
                    files.push(File {
                        directory: name.clone(),
                        name: file.file_name().to_string_lossy().into_owned(),
                        bytes: std::fs::read(file.path())?,
                    });
                }
            } else if path.is_file() {
                files.push(File { directory: String::new(), name, bytes: std::fs::read(&path)? });
            }
        }
        Ok(MigrationSet { files })
    }

    /// A set built from files in memory, for tests.
    pub fn of(files: Vec<File>) -> MigrationSet {
        MigrationSet { files }
    }

    pub fn files(&self) -> &[File] {
        &self.files
    }

    /// The migrations Flyway applies on `engine`, by version: `common`, then the engine's directory.
    ///
    /// As Flyway, a file whose name is not a migration's is skipped here — the layout rules
    /// (`layout::check`) are what refuse it. Two files of one version are refused, with Flyway's
    /// sentence. A repeatable (`R__`), undo (`U`) or baseline (`B`) migration is refused outright: the
    /// project has none, and running one with the semantics of a versioned migration would be wrong.
    pub fn resolve(&self, engine: Engine) -> Result<Vec<Resolved>, Error> {
        let mut resolved: Vec<Resolved> = Vec::new();
        for location in [COMMON, engine.vendor()] {
            for file in self.files.iter().filter(|file| file.directory == location) {
                let Some(stem) = file.name.strip_suffix(".sql") else { continue };
                if let Some(kind) = ["R__", "U", "B"].into_iter().find(|prefix| stem.starts_with(prefix)) {
                    return Err(Error::UnsupportedMigration { script: file.name.clone(), kind: kind.to_owned() });
                }
                let Some((version, description)) = parse_name(stem) else { continue };
                let checksum = checksum::of(&file.name, &file.bytes)?;
                let sql = String::from_utf8(file.bytes.clone())
                    .map_err(|_| Error::NotUtf8 { script: file.name.clone() })?;
                resolved.push(Resolved {
                    version,
                    description,
                    script: file.name.clone(),
                    directory: location.to_owned(),
                    checksum,
                    sql,
                });
            }
        }
        resolved.sort_by(|left, right| left.version.cmp(&right.version));
        if let Some(pair) = resolved.windows(2).find(|pair| pair[0].version == pair[1].version) {
            return Err(Error::DuplicateVersion {
                version: pair[0].version.to_string(),
                offenders: vec![
                    format!("{}/{}", pair[0].directory, pair[0].script),
                    format!("{}/{}", pair[1].directory, pair[1].script),
                ],
            });
        }
        Ok(resolved)
    }
}

/// `V91__checklist_contacts` → (91, "checklist contacts"), as `ResourceNameParser` reads a versioned
/// SQL migration's name with Flyway's defaults (prefix `V`, separator `__`, suffix `.sql`).
pub fn parse_name(stem: &str) -> Option<(Version, String)> {
    let rest = stem.strip_prefix('V')?;
    let (version, description) = rest.split_once("__")?;
    Some((Version::parse(version)?, description.replace('_', " ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(directory: &str, name: &str, sql: &str) -> File {
        File { directory: directory.to_owned(), name: name.to_owned(), bytes: sql.as_bytes().to_vec() }
    }

    #[test]
    fn a_name_is_read_as_flyway_reads_it() {
        let (version, description) = parse_name("V91__checklist_contacts").unwrap();
        assert_eq!(version.to_string(), "91");
        assert_eq!(description, "checklist contacts");
        assert!(parse_name("v91__x").is_none());
        assert!(parse_name("V91_x").is_none());
        assert!(parse_name("Vx__y").is_none());
    }

    #[test]
    fn common_and_the_engine_directory_are_read_and_nothing_else() {
        let set = MigrationSet::of(vec![
            file("common", "V40__shared.sql", "select 1;"),
            file("mysql", "V1__first.sql", "select 1;"),
            file("postgresql", "V1__first.sql", "select 2;"),
            file("mysql", "V2__second.sql", "select 1;"),
            file("common", "README.md", "not a migration"),
            file("elsewhere", "V3__ignored.sql", "select 1;"),
        ]);
        let mysql: Vec<_> = set.resolve(Engine::MySql).unwrap().into_iter().map(|m| m.script).collect();
        assert_eq!(mysql, ["V1__first.sql", "V2__second.sql", "V40__shared.sql"]);
        let postgres: Vec<_> = set.resolve(Engine::PostgreSql).unwrap().into_iter().map(|m| m.script).collect();
        assert_eq!(postgres, ["V1__first.sql", "V40__shared.sql"]);
    }

    #[test]
    fn a_version_found_twice_is_refused() {
        let set = MigrationSet::of(vec![
            file("common", "V40__shared.sql", "select 1;"),
            file("mysql", "V40__also.sql", "select 1;"),
        ]);
        assert!(matches!(set.resolve(Engine::MySql), Err(Error::DuplicateVersion { version, .. }) if version == "40"));
    }

    #[test]
    fn a_repeatable_migration_is_refused() {
        let set = MigrationSet::of(vec![file("common", "R__view.sql", "select 1;")]);
        assert!(matches!(set.resolve(Engine::MySql), Err(Error::UnsupportedMigration { .. })));
    }

    #[test]
    fn the_embedded_set_is_the_core_jar_s() {
        let set = MigrationSet::embedded();
        for engine in Engine::ALL {
            let resolved = set.resolve(engine).unwrap();
            // V1 to V90 on develop, without V83 and V85, which were never used.
            assert!(resolved.len() >= 88, "{engine:?}: {}", resolved.len());
            assert_eq!(resolved[0].version.to_string(), "1");
        }
    }
}

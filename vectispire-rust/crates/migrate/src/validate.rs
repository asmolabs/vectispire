//! What Flyway's `validate` decides before `migrate` touches anything, with the configuration the
//! control plane runs: `validateOnMigrate`, `outOfOrder=false`, `ignoreMigrationPatterns=*:future`,
//! plus `*:pending` added by `migrate` itself. A port of `MigrationInfoImpl.validate` and of the states
//! it reads, for versioned SQL migrations — the only kind this project has.
//!
//! The rules, each with the sentence Flyway prints:
//!
//! - an applied row with `success = false` refuses everything until someone repairs the database;
//! - an applied version no file resolves, below the newest file, is **missing**; above it, it is a
//!   **future** migration — a newer build's — and is accepted, as `*:future` accepts it;
//! - a file below the newest applied version that was never applied is **ignored**, refused with
//!   `outOfOrder=false`;
//! - an applied version whose file's checksum, description or type differs is a **mismatch**;
//! - a file above the newest applied version is **pending** — what `migrate` will apply.
//!
//! Rows Flyway writes for operations this runner does not implement (`BASELINE`, `DELETE` from
//! `repair`, `UNDO_*`) are refused rather than interpreted: the control plane's configuration never
//! produces one, and reading one wrong would apply or skip a migration silently.

use crate::history::Applied;
use crate::set::Resolved;
use crate::version::Version;

/// One thing validation refused, as Flyway words it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub message: String,
}

/// The outcome of validation: what is wrong, and what `migrate` would apply.
#[derive(Debug, Clone)]
pub struct Validation {
    pub problems: Vec<Problem>,
    /// Files above the newest applied version, in order.
    pub pending: Vec<Resolved>,
    /// Applied versions newer than any file: another build's, accepted.
    pub future: Vec<String>,
}

impl Validation {
    pub fn is_valid(&self) -> bool {
        self.problems.is_empty()
    }

    /// Flyway's `FlywayValidateException` text, without its link to the documentation.
    pub fn message(&self) -> String {
        let all: Vec<&str> = self.problems.iter().map(|problem| problem.message.as_str()).collect();
        format!("Validate failed: Migrations have failed validation\n{}", all.join("\n"))
    }
}

/// Validates the applied rows against the resolved files.
pub fn validate(resolved: &[Resolved], applied: &[Applied]) -> Validation {
    let mut problems = Vec::new();
    let mut future = Vec::new();

    // Flyway's `context.lastApplied`: the newest version among the rows, failed ones included.
    let last_applied: Option<Version> =
        applied.iter().filter(|row| row.kind == "SQL").filter_map(Applied::parsed_version).max();
    let latest_resolved: Option<&Version> = resolved.iter().map(|migration| &migration.version).max();

    for row in applied {
        match row.kind.as_str() {
            // The marker Flyway writes when it created the schema itself; it carries no migration.
            "SCHEMA" => continue,
            "SQL" => {}
            other => {
                problems.push(Problem {
                    message: format!(
                        "Schema history row {} is of type {other}, which this runner does not read (only SQL migrations \
                         are run by the control plane). Resolve it with the Java tooling first.",
                        row.installed_rank
                    ),
                });
                continue;
            }
        }
        let Some(version) = row.parsed_version() else {
            problems.push(Problem {
                message: format!(
                    "Schema history row {} is an SQL migration without a version: this runner reads no repeatable migration.",
                    row.installed_rank
                ),
            });
            continue;
        };
        let is_future = latest_resolved.is_none_or(|latest| version > *latest);
        let file = resolved.iter().find(|migration| migration.version == version);

        if !row.success {
            if is_future && file.is_none() {
                // FUTURE_FAILED, ignored by `*:future`; `migrate` still stops on it below.
                future.push(version.to_string());
                continue;
            }
            problems.push(Problem {
                message: format!(
                    "Detected failed migration to version {version} ({}).\nPlease remove any half-completed changes then \
                     run repair to fix the schema history.",
                    row.description
                ),
            });
            continue;
        }

        let Some(file) = file else {
            if is_future {
                future.push(version.to_string());
            } else {
                problems.push(Problem {
                    message: format!(
                        "Detected applied migration not resolved locally: {version}.\nIf you removed this migration \
                         intentionally, run repair to mark the migration as deleted."
                    ),
                });
            }
            continue;
        };

        let identifier = format!("version {}", row.version.as_deref().unwrap_or_default());
        if row.checksum != Some(file.checksum) {
            problems.push(mismatch(
                "checksum",
                &identifier,
                &row.checksum.map_or("null".to_owned(), |checksum| checksum.to_string()),
                &file.checksum.to_string(),
            ));
        } else if row.description != file.description {
            problems.push(mismatch("description", &identifier, &row.description, &file.description));
        }
    }

    let applied_versions: Vec<Version> = applied.iter().filter_map(Applied::parsed_version).collect();
    let mut pending = Vec::new();
    for migration in resolved {
        if applied_versions.contains(&migration.version) {
            continue;
        }
        match &last_applied {
            Some(last) if migration.version < *last => problems.push(Problem {
                message: format!(
                    "Detected resolved migration not applied to database: {}.\nTo ignore this migration, set \
                     -ignoreMigrationPatterns='*:ignored'. To allow executing this migration, set -outOfOrder=true.",
                    migration.version
                ),
            }),
            _ => pending.push(migration.clone()),
        }
    }

    Validation { problems, pending, future }
}

fn mismatch(what: &str, identifier: &str, applied: &str, resolved: &str) -> Problem {
    Problem {
        message: format!(
            "Migration {what} mismatch for migration {identifier}\n-> Applied to database : {applied}\n-> Resolved locally    : \
             {resolved}\nEither revert the changes to the migration, or run repair to update the schema history."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(version: &str, checksum: i32) -> Resolved {
        Resolved {
            version: Version::parse(version).unwrap(),
            description: format!("m{version}"),
            script: format!("V{version}__m{version}.sql"),
            directory: "common".to_owned(),
            checksum,
            sql: String::new(),
        }
    }

    fn row(rank: i32, version: &str, checksum: i32) -> Applied {
        Applied {
            installed_rank: rank,
            version: Some(version.to_owned()),
            description: format!("m{version}"),
            kind: "SQL".to_owned(),
            script: format!("V{version}__m{version}.sql"),
            checksum: Some(checksum),
            installed_by: "test".to_owned(),
            execution_time: 1,
            success: true,
        }
    }

    #[test]
    fn a_matching_history_is_valid_and_the_rest_pending() {
        let files = [file("1", 10), file("2", 20), file("3", 30)];
        let outcome = validate(&files, &[row(1, "1", 10), row(2, "2", 20)]);
        assert!(outcome.is_valid(), "{}", outcome.message());
        assert_eq!(outcome.pending.iter().map(|m| m.version.to_string()).collect::<Vec<_>>(), ["3"]);
    }

    #[test]
    fn a_changed_file_is_a_checksum_mismatch() {
        let outcome = validate(&[file("1", 11)], &[row(1, "1", 10)]);
        assert_eq!(outcome.problems.len(), 1);
        assert!(outcome.message().contains(
            "Migration checksum mismatch for migration version 1\n-> Applied to database : 10\n-> Resolved locally    : 11"
        ));
    }

    #[test]
    fn a_renamed_file_is_a_description_mismatch() {
        let mut renamed = file("1", 10);
        renamed.description = "another name".to_owned();
        let outcome = validate(&[renamed], &[row(1, "1", 10)]);
        assert!(outcome.message().contains("Migration description mismatch for migration version 1"));
    }

    #[test]
    fn an_applied_version_without_its_file_is_missing_unless_it_is_newer_than_every_file() {
        let missing = validate(&[file("1", 10), file("3", 30)], &[row(1, "1", 10), row(2, "2", 20), row(3, "3", 30)]);
        assert!(missing.message().contains("Detected applied migration not resolved locally: 2."));

        let future = validate(&[file("1", 10)], &[row(1, "1", 10), row(2, "2", 20)]);
        assert!(future.is_valid());
        assert_eq!(future.future, ["2"]);
    }

    #[test]
    fn a_file_older_than_the_newest_applied_version_is_refused_out_of_order() {
        let outcome = validate(&[file("1", 10), file("2", 20), file("3", 30)], &[row(1, "1", 10), row(2, "3", 30)]);
        assert!(outcome.message().contains("Detected resolved migration not applied to database: 2."));
        assert!(outcome.message().contains("-outOfOrder=true"));
    }

    #[test]
    fn a_failed_row_refuses_everything() {
        let mut failed = row(2, "2", 20);
        failed.success = false;
        let outcome = validate(&[file("1", 10), file("2", 20)], &[row(1, "1", 10), failed]);
        assert!(outcome.message().contains("Detected failed migration to version 2 (m2)."));
    }

    #[test]
    fn a_row_of_another_kind_is_refused_rather_than_read() {
        let mut baseline = row(1, "1", 10);
        baseline.kind = "BASELINE".to_owned();
        let outcome = validate(&[file("1", 10)], &[baseline]);
        assert!(outcome.message().contains("is of type BASELINE"));

        let mut marker = row(0, "0", 0);
        marker.kind = "SCHEMA".to_owned();
        marker.version = None;
        assert!(validate(&[file("1", 10)], &[marker]).is_valid());
    }
}

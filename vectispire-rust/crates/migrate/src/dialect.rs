//! The two engines, and the column types a common migration names without naming either — a port of
//! `MigrationDialect` and `MigrationPlaceholders` (decision 0027).
//!
//! **The values are as frozen as an applied migration.** Flyway does not replay what it has applied,
//! so changing one changes the columns of new installations only; the two populations then diverge
//! without an error. They are spelled here exactly as the Java enum spells them, and
//! `tests/placeholders.rs` reads `MigrationDialect.java` to prove it.

use std::collections::BTreeMap;

use crate::Error;

/// A database engine Vectispire has migrations for (decision 0014).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Engine {
    MySql,
    PostgreSql,
}

impl Engine {
    /// Both engines, in the order the Java enum declares them.
    pub const ALL: [Engine; 2] = [Engine::MySql, Engine::PostgreSql];

    /// Spring Boot's vendor id, and the directory under `db/migration` read after `common`.
    pub fn vendor(self) -> &'static str {
        match self {
            Engine::MySql => "mysql",
            Engine::PostgreSql => "postgresql",
        }
    }

    /// The engine for a vendor id, if it is one Vectispire has migrations for.
    pub fn of_vendor(vendor: &str) -> Option<Engine> {
        Engine::ALL.into_iter().find(|engine| engine.vendor() == vendor)
    }

    /// Placeholder name to the SQL it stands for, on this engine, in the Java enum's order.
    pub fn placeholders(self) -> [(&'static str, &'static str); 8] {
        match self {
            // `ts` stays `datetime(6)`: a bare `datetime` truncates to the second, and the audit
            // chain hashes a timestamp canonicalised to the millisecond (decision 0013).
            Engine::MySql => placeholders(
                "datetime(6)",
                "bigint auto_increment primary key",
                "bit(1)",
                "b'1'",
                "b'0'",
                "longtext",
                "double",
                "longblob",
            ),
            Engine::PostgreSql => placeholders(
                "timestamp with time zone",
                "bigint generated always as identity primary key",
                "boolean",
                "true",
                "false",
                "text",
                "double precision",
                "bytea",
            ),
        }
    }
}

/// Positional on purpose, as in Java: every engine answers every key, and a function taking eight
/// values cannot forget one the way a literal per engine could.
#[allow(clippy::too_many_arguments)]
fn placeholders(
    ts: &'static str,
    id: &'static str,
    bool: &'static str,
    yes: &'static str,
    no: &'static str,
    text: &'static str,
    double: &'static str,
    bytes: &'static str,
) -> [(&'static str, &'static str); 8] {
    [
        ("ts", ts),
        ("id", id),
        ("bool", bool),
        ("true", yes),
        ("false", no),
        ("text", text),
        ("double", double),
        ("bytes", bytes),
    ]
}

/// The placeholders a migration of `engine` is run with: the engine's types, plus whatever the
/// deployment configured (`spring.flyway.placeholders.*` on the Java side).
///
/// **A configured value cannot redefine a type.** Overriding `ts` with `datetime` would truncate the
/// audit chain's timestamps on MySQL through a setting nobody reviews as schema; it is refused with
/// `MigrationPlaceholders`' sentence. A configured value equal to the engine's is accepted, as in Java.
pub fn placeholders_for(
    engine: Engine,
    configured: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, Error> {
    let mut placeholders = configured.clone();
    for (name, value) in engine.placeholders() {
        if let Some(previous) = placeholders.insert(name.to_owned(), value.to_owned())
            && previous != value
        {
            return Err(Error::PlaceholderOverride {
                message: format!(
                    "spring.flyway.placeholders.{name} is set to \"{previous}\", but that placeholder is a column type \
                     Vectispire fixes per engine (\"{value}\" on {}). Remove the property: see decision 0027.",
                    engine.vendor()
                ),
            });
        }
    }
    Ok(placeholders)
}

/// Replaces every `${name}` in `sql`, as Flyway's `PlaceholderReplacingReader` does before parsing:
/// everywhere in the text, comments included; an unknown name, or a `${` never closed, is an error.
///
/// Flyway's own `${flyway:…}` placeholders are not provided — no migration uses one — and are refused
/// like any unknown name, so that the first migration to need one is ported on purpose.
pub fn replace(script: &str, sql: &str, placeholders: &BTreeMap<String, String>) -> Result<String, Error> {
    let mut out = String::with_capacity(sql.len());
    let mut rest = sql;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            // Flyway reads to the end of the file looking for the `}` and then fails the lookup.
            return Err(Error::UnknownPlaceholder { script: script.to_owned(), name: after.to_owned() });
        };
        let name = &after[..end];
        match placeholders.get(name) {
            Some(value) => out.push_str(value),
            None => {
                return Err(Error::UnknownPlaceholder { script: script.to_owned(), name: name.to_owned() });
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_engine_answers_every_placeholder_in_the_same_order() {
        let names = |engine: Engine| engine.placeholders().map(|(name, _)| name);
        assert_eq!(names(Engine::MySql), names(Engine::PostgreSql));
        for engine in Engine::ALL {
            assert!(engine.placeholders().iter().all(|(_, value)| !value.trim().is_empty()));
        }
    }

    #[test]
    fn mysql_keeps_the_audit_chain_precision_and_the_workbook_size() {
        let mysql: BTreeMap<_, _> = Engine::MySql.placeholders().into_iter().collect();
        assert_eq!(mysql["ts"], "datetime(6)");
        assert_eq!(mysql["bytes"], "longblob");
        let postgres: BTreeMap<_, _> = Engine::PostgreSql.placeholders().into_iter().collect();
        assert_eq!(postgres["bytes"], "bytea");
    }

    #[test]
    fn a_configured_type_is_refused_and_an_equal_one_accepted() {
        let mut configured = BTreeMap::new();
        configured.insert("ts".to_owned(), "datetime".to_owned());
        let refused = placeholders_for(Engine::MySql, &configured).unwrap_err().to_string();
        assert!(refused.contains("spring.flyway.placeholders.ts is set to \"datetime\""), "{refused}");
        assert!(refused.contains("(\"datetime(6)\" on mysql)"), "{refused}");

        configured.insert("ts".to_owned(), "datetime(6)".to_owned());
        configured.insert("other".to_owned(), "kept".to_owned());
        let accepted = placeholders_for(Engine::MySql, &configured).unwrap();
        assert_eq!(accepted["other"], "kept");
        assert_eq!(accepted.len(), 9);
    }

    #[test]
    fn placeholders_are_replaced_everywhere_and_an_unknown_one_refused() {
        let values = placeholders_for(Engine::PostgreSql, &BTreeMap::new()).unwrap();
        assert_eq!(
            replace("V1__x.sql", "-- ${ts}\nid ${id}, at ${ts}", &values).unwrap(),
            "-- timestamp with time zone\nid bigint generated always as identity primary key, at timestamp with time zone"
        );
        assert!(matches!(
            replace("V1__x.sql", "x ${flyway:user}", &values),
            Err(Error::UnknownPlaceholder { name, .. }) if name == "flyway:user"
        ));
        assert!(matches!(replace("V1__x.sql", "dangling ${ts", &values), Err(Error::UnknownPlaceholder { .. })));
    }
}

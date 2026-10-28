//! `wire_time.rs` on synthetic workspaces: a serialised instant names its format.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, config};
use vectispire_cp_arch_tests::wire_time::check;

fn violations(fixture: &Fixture) -> Vec<String> {
    let (violations, read) = check(&config(), &fixture.workspace());
    assert!(read >= 5, "the check read {read} files");
    violations
}

#[test]
fn the_clean_workspace_serialises_no_instant() {
    let found = violations(&Fixture::clean());
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn an_instant_with_the_default_format_fails() {
    let unnamed = [
        "#[derive(serde::Serialize)]\npub struct Entry { pub decided_at: Option<OffsetDateTime> }\n",
        "#[derive(Debug, Serialize)]\npub struct Entry { #[serde(rename = \"decidedAt\")] pub decided_at: time::OffsetDateTime }\n",
        "#[derive(Serialize)]\npub struct Entry { #[serde(default)] pub decided_at: Option<Date> }\n",
        "mod views { #[derive(Serialize)]\npub struct Entry { pub decided_at: PrimitiveDateTime } }\n",
    ];
    for text in unnamed {
        let fixture = Fixture::clean();
        fixture.append("vectispire-cp-issues", "src/lib.rs", text);
        let found = violations(&fixture);
        assert!(
            found.iter().any(|violation| violation.contains("vectispire-cp-issues: src/lib.rs: `Entry.decided_at`")),
            "{text}\n{found:#?}"
        );
    }
}

/// `time::serde::iso8601` names a format, and the wrong one: `+002026-10-27T…`, which Java never writes.
#[test]
fn an_instant_with_the_extended_year_fails() {
    for module in ["time::serde::iso8601", "time::serde::iso8601::option"] {
        let fixture = Fixture::clean();
        fixture.append(
            "vectispire-cp-issues",
            "src/lib.rs",
            &format!("#[derive(Serialize)]\npub struct Entry {{ #[serde(rename = \"at\", with = \"{module}\")] pub at: OffsetDateTime }}\n"),
        );
        let found = violations(&fixture);
        assert!(
            found.iter().any(|violation| violation.contains("`Entry.at` is serialised with `time::serde::iso8601`")),
            "{module}\n{found:#?}"
        );
    }
}

#[test]
fn an_instant_with_a_named_format_passes() {
    let named = [
        "#[derive(Serialize)]\npub struct Entry { #[serde(with = \"time::serde::rfc3339\")] pub at: OffsetDateTime }\n",
        "#[derive(Serialize)]\npub struct Entry { #[serde(rename = \"x\", default, with = \"time::serde::rfc3339::option\")] pub at: Option<OffsetDateTime> }\n",
        "#[derive(Serialize)]\npub struct Entry { #[serde(serialize_with = \"f\")] pub at: OffsetDateTime }\n",
        "#[derive(Serialize)]\npub struct Entry { #[serde(skip)] pub at: OffsetDateTime }\n",
        // Not serialised at all: a row, a decision held in memory.
        "#[derive(Debug, Clone)]\npub struct Row { pub at: OffsetDateTime }\n",
    ];
    for text in named {
        let fixture = Fixture::clean();
        fixture.append("vectispire-cp-issues", "src/lib.rs", text);
        let found = violations(&fixture);
        assert!(found.is_empty(), "{text}\n{found:#?}");
    }
}

//! An audit row as the evidence bundle's mapper writes `AuditLogEntity`: Jackson 2, `INDENT_OUTPUT`, the
//! default pretty printer — two spaces of indent, `" : "` between a name and its value, a line feed between
//! members — the entity's properties in its fields' declaration order, nulls written, the instant as
//! `ISO_INSTANT` text. Held to the Java bytes by the oracle suite (`tests/oracle.rs`).

use vectispire_domain::wire::write_string;

use crate::query::iso_instant;
use crate::record::StoredEntry;

fn member(out: &mut String, name: &str, value: Option<&str>, last: bool) {
    out.push_str("  ");
    write_string(out, name);
    out.push_str(" : ");
    match value {
        Some(value) => write_string(out, value),
        None => out.push_str("null"),
    }
    if !last {
        out.push(',');
    }
    out.push('\n');
}

/// One entry, as one indented document without a trailing line feed — `writeValueAsString(entity)`.
pub fn entity_document(entry: &StoredEntry) -> String {
    let mut out = String::from("{\n");
    member(&mut out, "id", Some(&entry.id.as_hyphenated().to_string()), false);
    member(&mut out, "description", Some(&entry.description), false);
    member(&mut out, "operationType", Some(&entry.operation_type), false);
    member(&mut out, "resourceId", Some(&entry.resource_id), false);
    member(&mut out, "timestamp", Some(&iso_instant(entry.timestamp)), false);
    member(&mut out, "userId", entry.user_id.as_deref(), false);
    member(&mut out, "ipAddress", entry.ip_address.as_deref(), false);
    member(&mut out, "userAgent", entry.user_agent.as_deref(), false);
    member(&mut out, "previousHash", entry.previous_hash.as_deref(), false);
    member(&mut out, "entryHash", entry.entry_hash.as_deref(), true);
    out.push('}');
    out
}

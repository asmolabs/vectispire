//! What a ticket says — `Tickets.title` and `Tickets.body` — and Jira's Atlassian Document Format. Pure: the
//! formatting is tested with no tracker.

use serde_json::{Value, json};
use vectispire_cp_issues::{FixState, TicketableIssue};
use vectispire_domain::Severity;
use vectispire_domain::dependency_graph::Directness;

/// How long a description may run inside a ticket body, in UTF-16 units.
const MAX_DESCRIPTION_LENGTH: usize = 1000;

fn blank(value: Option<&str>) -> bool {
    value.is_none_or(vectispire_domain::java::is_blank)
}

fn type_name(issue: &TicketableIssue) -> &str {
    issue.type_.map_or("null", |kind| kind.wire_name())
}

fn severity_of(issue: &TicketableIssue) -> Severity {
    issue.severity
}

/// Short enough for a ticket list, precise enough to be searchable.
pub fn title(issue: &TicketableIssue, target_name: &str) -> String {
    let subject = if blank(Some(&issue.identifier)) { type_name(issue) } else { issue.identifier.as_str() };
    let component = if blank(issue.package_name.as_deref()) {
        String::new()
    } else {
        format!(" — {}", issue.package_name.as_deref().unwrap_or_default())
    };
    let severity = vectispire_domain::java::to_upper_root(severity_of(issue).wire_name());
    format!("[Vectispire][{severity}] {subject}{component} ({target_name})")
}

/// The body, for whoever picks it up with no context — **the fixed version first among the details**.
pub fn body(issue: &TicketableIssue, target_name: &str) -> String {
    let mut lines = vec![
        format!("Detected by Vectispire on **{target_name}**."),
        String::new(),
        format!("- Type: {}", type_name(issue)),
        format!("- Identifier: {}", if blank(Some(&issue.identifier)) { "—" } else { issue.identifier.as_str() }),
        format!("- Severity: {}", severity_of(issue).wire_name()),
    ];
    if !blank(issue.fix_versions.as_deref()) {
        lines.push(format!("- **Fixed in: {}**", issue.fix_versions.as_deref().unwrap_or_default()));
    } else if matches!(issue.fix_state, FixState::NotFixed | FixState::WontFix) {
        lines.push("- No published fix to date".to_owned());
    }
    if !blank(issue.package_name.as_deref()) {
        let version = if blank(issue.package_version.as_deref()) {
            String::new()
        } else {
            format!(" {}", issue.package_version.as_deref().unwrap_or_default())
        };
        lines.push(format!("- Component: {}{version}", issue.package_name.as_deref().unwrap_or_default()));
    }
    if issue.directness != Directness::Unknown {
        lines.push(format!(
            "- Dependency: {}",
            if issue.directness == Directness::Direct { "direct (declared by the project)" } else { "transitive" }
        ));
    }
    if !blank(issue.file_path.as_deref()) {
        let line = issue.line.map(|line| format!(":{line}")).unwrap_or_default();
        lines.push(format!("- Location: {}{line}", issue.file_path.as_deref().unwrap_or_default()));
    }
    if issue.kev {
        lines.push("- ⚠️ Known active exploitation (CISA KEV catalog)".to_owned());
    }
    if let Some(epss) = issue.epss_score {
        lines.push(format!("- Exploitation probability (EPSS): {}%", one_decimal(epss * 100.0)));
    }
    if !blank(issue.link.as_deref()) {
        lines.push(format!("- Reference: {}", issue.link.as_deref().unwrap_or_default()));
    }
    if let Some(description) = issue.description.as_deref().filter(|d| !vectispire_domain::java::is_blank(d)) {
        // Truncated: a CVE description can run to several kilobytes.
        lines.push(String::new());
        let units: Vec<u16> = description.encode_utf16().collect();
        lines.push(if units.len() <= MAX_DESCRIPTION_LENGTH {
            description.to_owned()
        } else {
            vectispire_domain::java::from_utf16(units.get(..MAX_DESCRIPTION_LENGTH).unwrap_or_default())
        });
    }
    lines.push(String::new());
    lines.push(format!("Vectispire issue #{} — fingerprint `{}`.", issue.id, issue.fingerprint));
    lines.push(
        "This ticket was opened because this issue would fail a build under the gate policy in force for this target."
            .to_owned(),
    );
    lines.join("\n")
}

/// `String.format(Locale.ROOT, "%.1f", value)`: half-up rounding of the decimal value, as `Formatter` rounds.
fn one_decimal(value: f64) -> String {
    let text = format!("{value:.10}");
    let Some((whole, fraction)) = text.split_once('.') else { return format!("{text}.0") };
    let first: u32 = fraction.chars().next().and_then(|c| c.to_digit(10)).unwrap_or(0);
    let rest_up = fraction.chars().nth(1).and_then(|c| c.to_digit(10)).unwrap_or(0) >= 5;
    let negative = whole.starts_with('-');
    let mut units: i64 = whole.trim_start_matches('-').parse::<i64>().unwrap_or(0) * 10 + i64::from(first);
    if rest_up {
        units += 1;
    }
    format!("{}{}.{}", if negative { "-" } else { "" }, units / 10, units % 10)
}

/// Jira Cloud's v3 API refuses a plain string for `description`: one paragraph per non-blank line.
pub fn atlassian_document(body: &str) -> Value {
    let paragraphs: Vec<Value> = body
        .split('\n')
        .filter(|line| !vectispire_domain::java::is_blank(line))
        .map(|line| json!({"type": "paragraph", "content": [{"type": "text", "text": line}]}))
        .collect();
    json!({"type": "doc", "version": 1, "content": paragraphs})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epss_rounds_half_up_to_one_decimal() {
        assert_eq!(one_decimal(97.5), "97.5");
        assert_eq!(one_decimal(12.25), "12.3");
        assert_eq!(one_decimal(0.0), "0.0");
        assert_eq!(one_decimal(99.96), "100.0");
    }
}

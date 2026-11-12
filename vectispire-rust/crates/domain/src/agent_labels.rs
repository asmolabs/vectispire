//! `AgentLabels`: the labels an agent announces and the one a target may require, compared normalized.

use crate::java;

/// `parse`: split on `,`, each label `trim`-med and lower-cased (`Locale.ROOT`), empty ones dropped — without the
/// filter, an empty label would satisfy an empty requirement.
pub fn parse(raw: Option<&str>) -> Vec<String> {
    raw.map_or_else(Vec::new, |raw| {
        raw.split(',').map(|label| java::to_lower_root(java::trim(label))).filter(|label| !label.is_empty()).collect()
    })
}

/// `normalizeRequirement`: a requirement is exactly one label; none, or several (which no single agent label could
/// meet as written), is no requirement.
pub fn normalize_requirement(raw: Option<&str>) -> Option<String> {
    let mut labels = parse(raw);
    if labels.len() == 1 { labels.pop() } else { None }
}

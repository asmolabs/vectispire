//! The OWASP category a Semgrep rule declares about itself, read from its own words.
//!
//! A port of `OwaspTag`: reads metadata and refuses everything else.
//! Only the 2021 edition is accepted (`A01:2021` to `A10:2021`).

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

static CATEGORY_2021: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"(?-u:\b)(A0[1-9]|A10):2021(?-u:\b)").expect("a fixed pattern")
});

static OWASP_KEY: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"(?m)^(\s*)-?\s*owasp\s*:(.*)$").expect("a fixed pattern")
});

/// `OwaspTag.declaredIn`: extracts 2021 OWASP categories declared in the YAML text without parsing YAML.
pub fn declared_in(yaml: &str) -> Vec<String> {
    if yaml.trim().is_empty() {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();

    for caps in OWASP_KEY.captures_iter(yaml) {
        if let (Some(indent_match), Some(rest_match)) = (caps.get(1), caps.get(2)) {
            let indent = indent_match.as_str().len();
            collect_into(rest_match.as_str(), &mut found, &mut seen);

            let block_start = rest_match.end();
            if let Some(sub) = yaml.get(block_start..) {
                let block = extract_block(sub, indent);
                collect_into(&block, &mut found, &mut seen);
            }
        }
    }
    found
}

/// `OwaspTag.categoryOf`: the first 2021 category a declaration names.
pub fn category_of(declaration: &str) -> Option<String> {
    CATEGORY_2021.captures(declaration).and_then(|found| found.get(1)).map(|group| group.as_str().to_owned())
}

fn collect_into(text: &str, found: &mut Vec<String>, seen: &mut BTreeSet<String>) {
    for caps in CATEGORY_2021.captures_iter(text) {
        if let Some(cat) = caps.get(1) {
            let s = cat.as_str().to_owned();
            if seen.insert(s.clone()) {
                found.push(s);
            }
        }
    }
}

fn extract_block(rest: &str, parent_indent: usize) -> String {
    let mut inside = String::new();
    for line in rest.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        let leading = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
        if leading <= parent_indent {
            break;
        }
        inside.push_str(line);
        inside.push('\n');
    }
    inside
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_declared_categories() {
        let yaml = r#"
rules:
  - id: test-rule
    metadata:
      owasp:
        - A01:2017 - Injection
        - A03:2021 - Injection
        - A05:2021 - Security Misconfiguration
"#;
        assert_eq!(declared_in(yaml), vec!["A03", "A05"]);
    }

    #[test]
    fn extracts_inline_category() {
        let yaml = "owasp: A03:2021 - Injection\n";
        assert_eq!(declared_in(yaml), vec!["A03"]);
    }

    #[test]
    fn category_of_declaration() {
        assert_eq!(category_of("A03:2021 - Injection"), Some("A03".to_owned()));
        assert_eq!(category_of("A01:2017 - Injection"), None);
    }
}

//! `ChatText`: a value made inert for the markup of the chat it is posted to.
//!
//! Most of what a notification says was written by somebody else — a package name from the scanned manifest, a path
//! from its tree, a fix version from a scanner. Interpolated as they are, `<!channel>` pings a Slack channel and
//! `[Open in Vectispire](https://…)` is a link that reads as the product's own. Each chat has its own rule.

const ZERO_WIDTH_SPACE: char = '\u{200B}';

/// Slack's own rule: `&`, `<` and `>` as entities, and nothing else.
pub fn slack(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Discord markdown escaped with backslashes, and the two mass mentions broken by a zero-width space after `@`.
///
/// Java walks UTF-16 units; every character it escapes is ASCII, so walking chars is the same.
pub fn discord(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len().saturating_add(8));
    for c in value.chars() {
        if "\\*_~`|>[]()#<".contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
        if c == '@' {
            escaped.push(ZERO_WIDTH_SPACE);
        }
    }
    escaped
}

/// An Adaptive Card text block: Teams honours no backslash escape, so `](` and `{{` are split with a zero-width
/// space instead — the middle of a markdown link, and the card's templating.
pub fn teams(value: &str) -> String {
    value.replace("](", &format!("]{ZERO_WIDTH_SPACE}(")).replace("{{", &format!("{{{ZERO_WIDTH_SPACE}{{"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_chat_has_its_rule() {
        assert_eq!(slack("<!channel> & <https://x|y>"), "&lt;!channel&gt; &amp; &lt;https://x|y&gt;");
        assert_eq!(discord("[a](b) @everyone"), "\\[a\\]\\(b\\) @\u{200B}everyone");
        assert_eq!(teams("[a](b) {{DATE}}"), "[a]\u{200B}(b) {\u{200B}{DATE}}");
    }
}

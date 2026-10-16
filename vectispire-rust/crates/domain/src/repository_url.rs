//! Validation of a repository URL — a port of `RepositoryUrl`.
//!
//! **This is not input validation, it is a security control.** The URL lands in a clone run by
//! the agent: an uncontrolled value there is code execution on the machine doing the scanning
//! (`ext::` makes git run a command), and a URL read as one host by the checks and as another by
//! the clone is an SSRF. It is checked again before every clone, because rows can predate any
//! validation.
//!
//! **The Java class decides with `java.net.URI`, so this module reads URLs the way that class
//! does** — [`java_uri`] is a port of the JDK's RFC 2396 parser, down to which characters make it
//! throw and which authorities it gives no host. A different parser here would accept or refuse
//! URLs the control plane decided the other way about, and an operator would see a repository the
//! Java agent clones fail on the Rust one. The reference set `reference/repository-url/` holds the
//! Java answers for the inputs that tell the two parsers apart, and the tests read it.

use crate::net;
use regex::Regex;
use std::sync::LazyLock;

/// `user@host:path`. The path may not open with `//`: git reads that string as a local path, not
/// as a remote on `host`. (The negative look-ahead of the Java pattern is written as a check.)
static SCP_FORM: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)] // A literal pattern: a typo fails every test, not a request.
    Regex::new(r"^[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):([A-Za-z0-9._/-]+)$").expect("SCP pattern")
});

static HOST_NAME: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$")
        .expect("host name pattern")
});

/// The user part of a URL with a scheme: everything before the last `@` of the authority, which
/// ends at the first `/` only — not at `?` or `#`, as the transport reads it.
static USER_INFO: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/]*)@").expect("user-info pattern")
});

const ALLOWED_SCHEMES: [&str; 3] = ["https", "ssh", "git"];

const LINK_LOCAL_REFUSED: &str = "The URL points at a link-local or cloud metadata address, where the instance metadata \
     lives. Clone from the forge's own address.";

/// The host part of the SCP form, when `url` is one.
fn scp_host(url: &str) -> Option<(&str, &str)> {
    let captures = SCP_FORM.captures(url)?;
    let host = captures.get(1)?.as_str();
    let path = captures.get(2)?.as_str();
    if path.starts_with("//") {
        return None;
    }
    Some((host, path))
}

/// `None` if the URL is acceptable, otherwise the message to show.
pub fn validate(url: &str) -> Option<String> {
    if is_blank(url) {
        return Some("The repository URL is required.".to_owned());
    }
    if let Some((host, _)) = scp_host(url) {
        return net::is_link_local_literal(host).then(|| LINK_LOCAL_REFUSED.to_owned());
    }
    let Ok(parsed) = java_uri::parse(url) else {
        return Some("Invalid URL. Expected \"https://…\", \"ssh://…\" or \"git@host:path\".".to_owned());
    };
    let scheme = parsed.scheme.as_deref().unwrap_or("").to_lowercase();
    if !ALLOWED_SCHEMES.contains(&scheme.as_str()) {
        // `file://` would clone a local path on the agent; `ext::` makes git run a command. An
        // allowlist is the only safe shape — a denylist has to anticipate every future transport.
        return Some(format!("Scheme \"{scheme}\" is not allowed. Expected https, ssh or git."));
    }
    let Some(host) = parsed.host.as_deref().filter(|host| !host.is_empty()) else {
        return Some("The URL must name a host.".to_owned());
    };
    if let Some(ambiguous) = ambiguity(url, host) {
        return Some(ambiguous);
    }
    net::is_link_local_literal(host).then(|| LINK_LOCAL_REFUSED.to_owned())
}

/// The host a URL names, in either accepted form; `None` when there is none to read or when the
/// URL could be read as naming two.
pub fn host(url: &str) -> Option<String> {
    if let Some((host, _)) = scp_host(url) {
        return Some(host.to_owned());
    }
    let parsed = java_uri::parse(url).ok()?;
    let host = parsed.host.filter(|host| !host.is_empty())?;
    if ambiguity(url, &host).is_some() {
        return None;
    }
    Some(host)
}

/// Why a URL the URI parser reads could be read differently by the clone, or `None`.
///
/// Refuses what no git remote needs: the characters on which two URL readings part, a second
/// `@` or an escape in the authority, and any host the authority does not spell literally.
fn ambiguity(url: &str, parsed_host: &str) -> Option<String> {
    // Java iterates UTF-16 units; every unit this test names is ASCII, so code points read the same.
    if url.chars().any(|c| c <= '\u{20}' || c == '\u{7f}' || c == '#' || c == '?' || c == '\\') {
        return Some(
            "The URL contains a character a repository address does not need (a space, '#', '?' or '\\'). Use the \
             address the forge gives for cloning."
                .to_owned(),
        );
    }
    let Some(scheme_end) = url.find("://") else {
        return Some("The URL must name a host.".to_owned());
    };
    let scheme = &url[..scheme_end];
    if scheme != scheme.to_lowercase() {
        return Some(format!("Write the scheme in lower case: \"{}://\".", scheme.to_lowercase()));
    }
    let after = &url[scheme_end + 3..];
    let authority = after.find('/').map_or(after, |end| &after[..end]);
    let at = authority.find('@');
    if at != authority.rfind('@') || authority.contains('%') {
        return Some("The URL's host part is ambiguous: at most one '@', and no escaped character.".to_owned());
    }
    let host_and_port = at.map_or(authority, |at| &authority[at + 1..]);
    let spelled = if host_and_port.starts_with('[') {
        host_and_port.find(']').map_or(host_and_port, |close| &host_and_port[..=close])
    } else {
        host_and_port.find(':').map_or(host_and_port, |colon| &host_and_port[..colon])
    };
    if !spelled.eq_ignore_ascii_case(parsed_host) {
        return Some("The URL's host part is ambiguous. Use the address the forge gives for cloning.".to_owned());
    }
    None
}

/// Whether the URL clones over HTTPS — the only transport an HTTPS token is for.
pub fn is_https(url: &str) -> bool {
    url.trim().to_lowercase().starts_with("https://")
}

/// Why a host cannot be a token's host.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidHost(pub String);

/// A host as a token is bound to it: lower case, no trailing dot, no port, no scheme.
pub fn normalize_host(host: &str) -> Result<String, InvalidHost> {
    let mut value = host.trim().to_lowercase();
    while value.ends_with('.') {
        value.pop();
    }
    if value.is_empty() || value.len() > 253 || !HOST_NAME.is_match(&value) {
        return Err(InvalidHost(
            "Expected a host name such as gitlab.example.com — no scheme, port or path.".to_owned(),
        ));
    }
    if net::is_link_local_literal(&value) {
        return Err(InvalidHost(LINK_LOCAL_REFUSED.to_owned()));
    }
    Ok(value)
}

/// Whether the URL's host is `host`, compared as [`normalize_host`] writes both.
pub fn has_host(url: &str, host: &str) -> bool {
    self::host(url).and_then(|found| Some(normalize_host(&found).ok()? == normalize_host(host).ok()?)).unwrap_or(false)
}

/// The URL with any credential it carries replaced by `***`, for everything but the clone.
///
/// `ssh://git@host` keeps its user: over SSH that is a login name, never the secret. Over HTTPS
/// any user part is masked, since a token is commonly passed as the user name alone.
pub fn redact(url: &str) -> String {
    let Some(captures) = USER_INFO.captures(url) else {
        return url.to_owned();
    };
    let (Some(whole), Some(scheme), Some(user)) = (captures.get(0), captures.get(1), captures.get(2)) else {
        return url.to_owned();
    };
    let ssh_login = scheme.as_str().eq_ignore_ascii_case("ssh://") && !user.as_str().contains(':');
    if ssh_login { url.to_owned() } else { format!("{}***@{}", scheme.as_str(), &url[whole.end()..]) }
}

/// `String.isBlank`: empty or only white space, as Java's `Character.isWhitespace` reads it.
fn is_blank(value: &str) -> bool {
    value.chars().all(java_uri::is_java_whitespace)
}

/// A port of the parser behind `java.net.URI(String)`, reduced to what [`validate`] reads: whether
/// it throws, the scheme, and the host — absent for an opaque URI or a registry-based authority.
pub mod java_uri {
    /// What the JDK's parser gives back.
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct Parsed {
        /// The scheme as written, when there is one.
        pub scheme: Option<String>,
        /// The host as `URI.getHost` returns it — an IPv6 literal with its brackets.
        pub host: Option<String>,
    }

    /// The URI does not parse: the JDK would throw `URISyntaxException`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Syntax;

    const ALPHA: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGIT: &str = "0123456789";

    #[derive(Clone, Copy)]
    struct Class {
        chars: &'static str,
        alnum: bool,
        escaped: bool,
    }

    const SCHEME: Class = Class { chars: "+-.", alnum: true, escaped: false };
    const URIC: Class = Class { chars: ";/?:@&=+$,[]_-!.~'()*", alnum: true, escaped: true };
    const PATH: Class = Class { chars: ":@&=+$,;/_-!.~'()*", alnum: true, escaped: true };
    const USER_INFO: Class = Class { chars: ",;:$&+=_-!.~'()*", alnum: true, escaped: true };
    const REG_NAME: Class = Class { chars: "$,;:@&=+_-!.~'()*", alnum: true, escaped: true };
    const SERVER: Class = Class { chars: ",;:$&+=_-!.~'()*-.:@[]", alnum: true, escaped: true };

    fn matches(class: Class, c: char) -> bool {
        (class.alnum && c.is_ascii_alphanumeric()) || (c.is_ascii() && class.chars.contains(c))
    }

    /// `Character.isSpaceChar`: the Unicode space separators.
    fn is_space_char(c: char) -> bool {
        matches!(
            c,
            '\u{20}' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
        )
    }

    fn is_iso_control(c: char) -> bool {
        matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
    }

    /// `Character.isWhitespace`, which `String.isBlank` asks.
    pub(crate) fn is_java_whitespace(c: char) -> bool {
        matches!(c, '\u{9}'..='\u{d}' | '\u{1c}'..='\u{1f}')
            || (is_space_char(c) && !matches!(c, '\u{a0}' | '\u{2007}' | '\u{202f}'))
    }

    struct Parser {
        input: Vec<char>,
        scheme: Option<String>,
        host: Option<String>,
    }

    /// Parses as `new URI(text)` does.
    pub fn parse(text: &str) -> Result<Parsed, Syntax> {
        let mut parser = Parser { input: text.chars().collect(), scheme: None, host: None };
        parser.parse()?;
        Ok(Parsed { scheme: parser.scheme, host: parser.host })
    }

    impl Parser {
        fn n(&self) -> usize {
            self.input.len()
        }

        fn at(&self, p: usize, end: usize, c: char) -> bool {
            p < end && self.input[p] == c
        }

        fn substring(&self, start: usize, end: usize) -> String {
            self.input[start..end].iter().collect()
        }

        /// `scan(start, end, err, stop)`: `None` on a char of `err`, else where `stop` starts.
        fn scan_until(&self, start: usize, end: usize, err: &str, stop: &str) -> Option<usize> {
            let mut p = start;
            while p < end {
                let c = self.input[p];
                if err.contains(c) {
                    return None;
                }
                if stop.contains(c) {
                    break;
                }
                p += 1;
            }
            Some(p)
        }

        /// `scan(start, end, mask)`: how far the class reaches, escapes and other chars included where
        /// the class allows escapes. A malformed escape throws, as the JDK does.
        fn scan_class(&self, start: usize, end: usize, class: Class) -> Result<usize, Syntax> {
            let mut p = start;
            while p < end {
                let c = self.input[p];
                if matches(class, c) {
                    p += 1;
                    continue;
                }
                if class.escaped {
                    if c == '%' {
                        if p + 3 <= end
                            && self.input[p + 1].is_ascii_hexdigit()
                            && self.input[p + 2].is_ascii_hexdigit()
                        {
                            p += 3;
                            continue;
                        }
                        return Err(Syntax);
                    }
                    if (c as u32) > 128 && !is_space_char(c) && !is_iso_control(c) {
                        p += 1;
                        continue;
                    }
                }
                break;
            }
            Ok(p)
        }

        fn check(&self, start: usize, end: usize, class: Class) -> Result<(), Syntax> {
            if self.scan_class(start, end, class)? < end { Err(Syntax) } else { Ok(()) }
        }

        fn parse(&mut self) -> Result<(), Syntax> {
            let n = self.n();
            let colon = self.scan_until(0, n, "/?#", ":");
            let mut p;
            match colon {
                Some(position) if self.at(position, n, ':') => {
                    if position == 0 || !ALPHA.contains(self.input[0]) {
                        return Err(Syntax);
                    }
                    self.check(1, position, SCHEME)?;
                    self.scheme = Some(self.substring(0, position));
                    p = position + 1;
                    if self.at(p, n, '/') {
                        p = self.parse_hierarchical(p, n)?;
                    } else {
                        let q = self.scan_until(p, n, "", "#").unwrap_or(n);
                        if q <= p {
                            return Err(Syntax);
                        }
                        self.check(p, q, URIC)?;
                        p = q;
                    }
                }
                _ => p = self.parse_hierarchical(0, n)?,
            }
            if self.at(p, n, '#') {
                self.check(p + 1, n, URIC)?;
                p = n;
            }
            if p < n { Err(Syntax) } else { Ok(()) }
        }

        fn parse_hierarchical(&mut self, start: usize, n: usize) -> Result<usize, Syntax> {
            let mut p = start;
            if self.at(p, n, '/') && self.at(p + 1, n, '/') {
                p += 2;
                let q = self.scan_until(p, n, "", "/?#").unwrap_or(n);
                if q > p {
                    p = self.parse_authority(p, q)?;
                } else if q >= n {
                    return Err(Syntax);
                }
            }
            let q = self.scan_until(p, n, "", "?#").unwrap_or(n);
            self.check(p, q, PATH)?;
            p = q;
            if self.at(p, n, '?') {
                p += 1;
                let q = self.scan_until(p, n, "", "#").unwrap_or(n);
                self.check(p, q, URIC)?;
                p = q;
            }
            Ok(p)
        }

        fn parse_authority(&mut self, start: usize, n: usize) -> Result<usize, Syntax> {
            let server_chars = self.scan_class(start, n, SERVER)? == n;
            let reg_chars = self.scan_class(start, n, REG_NAME)? == n;
            if reg_chars && !server_chars {
                return Ok(n);
            }
            // A server-based authority that does not parse is read as a registry-based one when its
            // characters allow it — and a registry-based authority has no host.
            let mut q = start;
            if server_chars {
                match self.parse_server(start, n) {
                    Ok(end) if end >= n => q = end,
                    _ => self.host = None,
                }
            }
            if q < n {
                if !reg_chars {
                    return Err(Syntax);
                }
                self.host = None;
            }
            Ok(n)
        }

        fn parse_server(&mut self, start: usize, n: usize) -> Result<usize, Syntax> {
            let mut p = start;
            if let Some(q) = self.scan_until(p, n, "/?#", "@")
                && self.at(q, n, '@')
            {
                self.check(p, q, USER_INFO)?;
                p = q + 1;
            }
            if self.at(p, n, '[') {
                p += 1;
                let q = self.scan_until(p, n, "/?#", "]").ok_or(Syntax)?;
                if !(q > p && self.at(q, n, ']')) {
                    return Err(Syntax);
                }
                let r = self.scan_until(p, q, "", "%").unwrap_or(q);
                let address = self.substring(p, r);
                if r <= p || address.parse::<std::net::Ipv6Addr>().is_err() {
                    return Err(Syntax);
                }
                if r < q {
                    // A scope id: the JDK checks it as alphanumerics and a few marks.
                    if r + 1 == q {
                        return Err(Syntax);
                    }
                    self.check(r + 1, q, Class { chars: "_-.", alnum: true, escaped: false })?;
                }
                self.host = Some(self.substring(p - 1, q + 1));
                p = q + 1;
            } else {
                let q = match self.parse_ipv4(p, n) {
                    Some(end) => end,
                    None => self.parse_hostname(p, n)?,
                };
                p = q;
            }
            if self.at(p, n, ':') {
                p += 1;
                let q = self.scan_until(p, n, "", "/").unwrap_or(n);
                if q > p {
                    self.check(p, q, DIGITS_ONLY)?;
                    self.substring(p, q).parse::<i32>().map_err(|_| Syntax)?;
                    p = q;
                }
            }
            if p < n {
                return Err(Syntax);
            }
            Ok(p)
        }

        /// `parseIPv4Address`: four bytes of at most 255, followed by nothing or a `:`.
        fn parse_ipv4(&mut self, start: usize, n: usize) -> Option<usize> {
            let mut m = start;
            while m < n && (self.input[m].is_ascii_digit() || self.input[m] == '.') {
                m += 1;
            }
            if m <= start {
                return None;
            }
            let mut p = start;
            for index in 0..4 {
                if index > 0 {
                    if !self.at(p, m, '.') {
                        return None;
                    }
                    p += 1;
                }
                let begin = p;
                while p < m && self.input[p].is_ascii_digit() {
                    p += 1;
                }
                if p == begin || self.substring(begin, p).parse::<u32>().map_or(true, |value| value > 255) {
                    return None;
                }
            }
            if p < m {
                return None;
            }
            if p < n && self.input[p] != ':' {
                return None;
            }
            self.host = Some(self.substring(start, p));
            Some(p)
        }

        /// `parseHostname`: labels of alphanumerics with inner dashes, the last starting with a letter.
        fn parse_hostname(&mut self, start: usize, n: usize) -> Result<usize, Syntax> {
            let mut p = start;
            let mut last_label: Option<usize> = None;
            loop {
                let mut q = p;
                while q < n && self.input[q].is_ascii_alphanumeric() {
                    q += 1;
                }
                if q <= p {
                    break;
                }
                last_label = Some(p);
                p = q;
                let mut rest = p;
                while rest < n && (self.input[rest].is_ascii_alphanumeric() || self.input[rest] == '-') {
                    rest += 1;
                }
                if rest > p {
                    if self.input[rest - 1] == '-' {
                        return Err(Syntax);
                    }
                    p = rest;
                }
                if !self.at(p, n, '.') {
                    break;
                }
                p += 1;
                if p >= n {
                    break;
                }
            }
            if p < n && !self.at(p, n, ':') {
                return Err(Syntax);
            }
            let label = last_label.ok_or(Syntax)?;
            if label > start && !ALPHA.contains(self.input[label]) {
                return Err(Syntax);
            }
            self.host = Some(self.substring(start, p));
            Ok(p)
        }
    }

    const DIGITS_ONLY: Class = Class { chars: DIGIT, alnum: false, escaped: false };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forms_a_forge_gives_are_accepted() {
        for url in [
            "https://gitlab.example.org/team/api.git",
            "ssh://git@gitlab.example.org:2222/team/api.git",
            "git@gitlab.example.org:team/api.git",
            "git://git.example.org/repo",
            "https://10.0.0.5/team/api",
        ] {
            assert_eq!(validate(url), None, "{url}");
        }
    }

    #[test]
    fn what_makes_git_run_a_command_or_read_a_file_is_refused() {
        for url in ["ext::sh -c touch% /tmp/pwned", "file:///etc/passwd", "fd::17/foo", "/srv/repo.git"] {
            assert!(validate(url).is_some(), "{url} should be refused");
        }
    }

    #[test]
    fn a_host_read_two_ways_is_refused() {
        for url in [
            "https://user#@evil.example/x",
            "https://a@b@gitlab.example.org/x",
            "HTTPS://gitlab.example.org/x",
            "https://gitlab.example.org%2eevil/x",
        ] {
            assert!(validate(url).is_some(), "{url} should be refused");
            assert_eq!(host(url), None, "{url} names no single host");
        }
    }

    #[test]
    fn the_metadata_endpoint_is_refused_in_both_forms() {
        for url in ["https://169.254.169.254/latest", "git@169.254.169.254:x", "git@169.254.43518:x"] {
            assert!(validate(url).is_some_and(|refusal| refusal.contains("link-local")), "{url}");
        }
    }

    #[test]
    fn a_token_never_shows() {
        assert_eq!(redact("https://user:token@gitlab.example.org/x"), "https://***@gitlab.example.org/x");
        assert_eq!(redact("ssh://git@gitlab.example.org/x"), "ssh://git@gitlab.example.org/x");
        assert_eq!(redact("https://gitlab.example.org/x"), "https://gitlab.example.org/x");
    }
}

//! A proof's link as `new URI(link)` reads it: an `https` or `http` scheme, and a server-based authority with a host
//! — what `URI.getHost()` answers non-null for. A link `URI` refuses to parse is refused in the same words.

/// Characters `java.net.URI` accepts unescaped in a hierarchical URI (RFC 2396's `uric`, `%` for an escape, and
/// the brackets of an IPv6 literal); anything else — a space, `<`, `"` — is a `URISyntaxException`.
fn uri_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || "-_.!~*'();/?:@&=+$,%#[]".contains(c)
        || !c.is_ascii() && !c.is_control() && !c.is_whitespace()
}

/// Whether `link` is an `http:` or `https:` URI with a host.
pub(crate) fn has_web_host(link: &str) -> bool {
    if !link.chars().all(uri_char) || link.matches('#').count() > 1 {
        return false;
    }
    let Some((scheme, rest)) = link.split_once(':') else { return false };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return false;
    }
    let Some(rest) = rest.strip_prefix("//") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    if let Some(literal) = host_port.strip_prefix('[') {
        return literal.split_once(']').is_some_and(|(address, tail)| {
            !address.is_empty()
                && address.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
                && (tail.is_empty()
                    || tail.strip_prefix(':').is_some_and(|port| port.chars().all(|c| c.is_ascii_digit())))
        });
    }
    let (host, port) = host_port.rsplit_once(':').unwrap_or((host_port, ""));
    if !port.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // A server-based authority's host: dot-separated labels of letters, digits and inner hyphens, the last not
    // starting with a digit unless the whole host is an IPv4 address. Anything else is registry-based: no host.
    if host.is_empty() {
        return false;
    }
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    let label_ok = |label: &&str| {
        !label.is_empty()
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    if !labels.iter().all(label_ok) {
        return false;
    }
    let ipv4 = labels.len() == 4 && labels.iter().all(|label| label.chars().all(|c| c.is_ascii_digit()));
    ipv4 || labels.last().is_some_and(|last| last.chars().next().is_some_and(|c| c.is_ascii_alphabetic()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_links_with_a_host() {
        for link in
            ["https://example.org/report", "http://10.0.0.1:8080/x?y=1#z", "HTTPS://a.b-c.example", "https://[::1]/"]
        {
            assert!(has_web_host(link), "{link}");
        }
        for link in [
            "ftp://example.org",
            "https:///path",
            "https://exa mple.org",
            "javascript:alert(1)",
            "https:example.org",
            "https://under_score.example/",
        ] {
            assert!(!has_web_host(link), "{link}");
        }
    }
}

//! A SIEM endpoint is typed by an operator and read for each protocol: whatever is typed, reading it must answer,
//! never panic — and what it accepts for syslog is a host with no path, no space and a port the socket can use, a
//! host of digits and dots no longer than an IPv4 literal can be; for a webhook, a URL whose port, if any, is one.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_domain::repository_url::java_uri;
use vectispire_domain::siem::endpoint::{self, SiemEndpoint};
use vectispire_domain::siem::SiemProtocol;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    for protocol in SiemProtocol::ALL {
        match endpoint::parse(protocol, Some(text)) {
            Ok(SiemEndpoint::Syslog { protocol: read, host, port }) => {
                assert_eq!(read, protocol);
                assert!(port >= 1, "port 0 accepted");
                assert!(!host.is_empty() && !host.contains(['/', ' ', '[', ']']), "a host that is not one: {host:?}");
                if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
                    assert!(host.len() <= 16 && !host.contains(".."), "no IPv4 literal: {host:?}");
                }
            }
            Ok(SiemEndpoint::Webhook { url }) => {
                assert_eq!(protocol, SiemProtocol::Webhook);
                assert!(!url.is_empty());
                let port = java_uri::parse(&url).ok().and_then(|uri| uri.port);
                assert!(port.is_none_or(|port| (1..=65_535).contains(&port)), "port {port:?} accepted");
            }
            Err(refused) => assert!(!refused.0.is_empty()),
        }
    }
});

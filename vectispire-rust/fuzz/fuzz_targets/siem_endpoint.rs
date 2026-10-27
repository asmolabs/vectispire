//! A SIEM endpoint is typed by an operator and read for each protocol: whatever is typed, reading it must answer,
//! never panic — and what it accepts for syslog is a host with no path, no space and a port the socket can use.
#![no_main]

use libfuzzer_sys::fuzz_target;
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
            }
            Ok(SiemEndpoint::Webhook { url }) => {
                assert_eq!(protocol, SiemProtocol::Webhook);
                assert!(!url.is_empty());
            }
            Err(refused) => assert!(!refused.0.is_empty()),
        }
    }
});

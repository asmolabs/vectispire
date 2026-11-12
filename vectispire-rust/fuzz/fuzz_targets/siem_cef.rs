//! Audit text — a username somebody typed, a description, a resource id — reaches a SOC as CEF fields and a syslog
//! header. Whatever it holds, the line stays one line, the header keeps its seven fields, an extension value
//! names no field of its own, and the syslog header keeps its tokens: a forged second event or a shifted field is
//! the injection the escaping exists to stop. The input is the value, a NUL, then the hostname.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_domain::instant::Instant;
use vectispire_domain::siem::{CefEvent, SecurityEventType, syslog};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let (value, hostname) = text.split_once('\0').unwrap_or((text, ""));
    let Ok(event) = CefEvent::builder(SecurityEventType::SignInThrottled, Instant::of_epoch_second(0))
        .user(value)
        .message(value)
        .build()
    else {
        return;
    };
    let line = event.to_cef_string(Some(value));
    assert!(!line.contains(['\n', '\r', '\u{2028}', '\u{2029}', '\u{85}']), "the line breaks");
    assert!(!line.chars().any(|c| c < ' ' || c == '\u{7f}'), "a control character survives");
    // The header's unescaped pipes: seven, whatever the version field held.
    let mut pipes = 0;
    let mut escaped = false;
    let mut extension = String::new();
    for c in line.chars() {
        if pipes == 7 {
            extension.push(c);
            continue;
        }
        match (escaped, c) {
            (false, '\\') => escaped = true,
            (false, '|') => pipes += 1,
            _ => escaped = false,
        }
    }
    assert_eq!(pipes, 7, "the header lost or gained a field");
    // In the extension, every `=` is a field's own or escaped: `rt`, `outcome`, `suser`, `msg` and no other.
    let mut fields = 0;
    let mut escaped = false;
    for c in extension.chars() {
        match (escaped, c) {
            (false, '\\') => escaped = true,
            (false, '=') => fields += 1,
            _ => escaped = false,
        }
    }
    let expected = if vectispire_domain::java::is_blank(value) { 2 } else { 4 };
    assert_eq!(fields, expected, "a value forged a field");

    let message = syslog::format(&event, Some(hostname), &line);
    let header: Vec<&str> = message.splitn(8, ' ').collect();
    assert_eq!(header.len(), 8, "the syslog header lost a token");
    assert_eq!(header[3], syslog::APP_NAME, "the hostname shifted the header");
    assert!(header[2].chars().all(|c| c.is_ascii_graphic()) && header[2].len() <= 255);
    let frame = syslog::octet_counted(&message);
    assert!(frame.starts_with(format!("{} ", message.len()).as_bytes()));
});

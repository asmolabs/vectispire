//! The SIEM domain's behaviour, case for case from the Java tests of `common.domain.siem`: `CefEventTest`,
//! `SyslogMessageTest`, `SiemEndpointTest`, `SecurityEventTypeTest`, `SiemSeverityFilterTest`,
//! `TriageSignalsTest` and `SecurityEventCatalogueDocsTest`. `CollectorCaTest`'s are in `collector_ca.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;

use vectispire_domain::instant::Instant;
use vectispire_domain::severity::Severity;
use vectispire_domain::siem::endpoint::{self, SiemEndpoint};
use vectispire_domain::siem::event_type::{self, Placement};
use vectispire_domain::siem::{
    CefEvent, Outcome, SecurityEventType as E, SiemProtocol, severity_filter, signalled_by, syslog, triage_signals,
};

/// `2026-09-26T10:00:00Z`.
const TS: Instant = Instant { epoch_second: 1_790_416_800, nano: 0 };
/// `2026-09-26T10:00:00.123Z`.
const TS_MILLIS: Instant = Instant { epoch_second: 1_790_416_800, nano: 123_000_000 };

// --- CefEventTest ---

#[test]
fn formats_the_header_and_the_standard_extension_fields() {
    let event = CefEvent::builder(E::ApiKeyIssued, TS)
        .message("API key issued: ci-pipeline")
        .user("alice")
        .source_ip("203.0.113.7")
        .action("API_KEY_CREATED")
        .target("42")
        .build()
        .unwrap();

    let cef = event.to_cef_string(Some("2.3.0"));

    assert!(cef.starts_with("CEF:0|Vectispire|ASPM|2.3.0|VECTI-SEC-012|API key issued|5|"), "{cef}");
    assert!(cef.contains("rt=1790416800000"));
    assert!(cef.contains("outcome=success"));
    assert!(cef.contains("suser=alice"));
    assert!(cef.contains("src=203.0.113.7"));
    assert!(cef.contains("act=API_KEY_CREATED"));
    assert!(cef.contains("cs1Label=Target cs1=42"));
    assert!(cef.ends_with("msg=API key issued: ci-pipeline"));
    // The whole line, so that the order of the fields is pinned too.
    assert_eq!(
        cef,
        "CEF:0|Vectispire|ASPM|2.3.0|VECTI-SEC-012|API key issued|5|rt=1790416800000 outcome=success suser=alice \
         src=203.0.113.7 act=API_KEY_CREATED cs1Label=Target cs1=42 msg=API key issued: ci-pipeline"
    );
}

#[test]
fn a_deadline_breach_states_its_issue_s_severity_in_the_header_any_other_event_its_type_s() {
    let line = |severity: Option<Severity>| {
        let builder = CefEvent::builder(E::SlaBreached, TS);
        let builder = match severity {
            Some(severity) => builder.issue_severity(severity),
            None => builder,
        };
        builder.build().unwrap().to_cef_string(Some("1"))
    };
    assert!(
        line(Some(Severity::Critical))
            .starts_with("CEF:0|Vectispire|ASPM|1|VECTI-SEC-030|Remediation deadline passed|8|")
    );
    assert!(line(Some(Severity::Low)).contains("|Remediation deadline passed|3|"));
    // Without an issue's severity — an event queued before it was stored — the type's.
    assert!(line(None).contains("|Remediation deadline passed|6|"));
}

#[test]
fn a_type_with_a_fixed_severity_refuses_an_issue_s_and_no_severity_leaves_the_cef_scale() {
    let refused = CefEvent::builder(E::SecretLeakDetected, TS).issue_severity(Severity::Low).build().unwrap_err();
    assert_eq!(refused.0, "SECRET_LEAK_DETECTED has a fixed CEF severity");
    assert_eq!(CefEvent::new(E::SlaBreached, TS, None, &[], 11).unwrap_err().0, "A CEF severity is 0 to 10, not 11");
    assert_eq!(CefEvent::new(E::SlaBreached, TS, None, &[], -1).unwrap_err().0, "A CEF severity is 0 to 10, not -1");
    assert_eq!(CefEvent::new(E::SlaBreached, TS, None, &[], 10).unwrap().cef_severity(), 10);
    assert_eq!(CefEvent::new(E::SlaBreached, TS, None, &[], 0).unwrap().cef_severity(), 0);
}

#[test]
fn an_unknown_product_version_leaves_the_field_empty_rather_than_inventing_one() {
    let cef = CefEvent::builder(E::PingTest, TS).build().unwrap().to_cef_string(None);
    assert!(cef.starts_with("CEF:0|Vectispire|ASPM||VECTI-SEC-999|"), "{cef}");
}

#[test]
fn escapes_backslash_and_equals_in_extension_values_and_leaves_a_pipe_alone_there() {
    let event = CefEvent::builder(E::SecurityGateFailed, TS).message("Policy failed: Rule|A=B \\ end").build().unwrap();
    assert!(event.to_cef_string(Some("1")).contains("msg=Policy failed: Rule|A\\=B \\\\ end"));
}

#[test]
fn an_attacker_chosen_username_cannot_forge_a_second_event_or_a_new_field() {
    // Typed into the sign-in form, recorded as the audit entry's user, forwarded as suser.
    let typed = "mallory\nCEF:0|Vectispire|ASPM|1|VECTI-SEC-018|forged|10|suser=admin\r\nsrc=1.2.3.4 act=x";

    let cef = CefEvent::builder(E::SignInThrottled, TS).user(typed).build().unwrap().to_cef_string(Some("1"));

    // One line, whatever the collector splits on.
    assert!(!cef.contains('\n') && !cef.contains('\r'));
    // The equals signs are escaped, so no parser reads "src=" or "suser=" as a field of ours.
    assert!(cef.contains(
        "suser=mallory\\nCEF:0|Vectispire|ASPM|1|VECTI-SEC-018|forged|10|suser\\=admin\\r\\nsrc\\=1.2.3.4 act\\=x"
    ));
    // Exactly one unescaped "suser=" and no unescaped "src=".
    let unescaped = |field: &str| cef.match_indices(field).filter(|(at, _)| !cef[..*at].ends_with('\\')).count();
    assert_eq!(unescaped("suser="), 1);
    assert_eq!(unescaped("src="), 0);
}

#[test]
fn control_characters_and_unicode_line_separators_become_spaces() {
    let cef = CefEvent::builder(E::SignInThrottled, TS)
        .user("a\u{0}b\u{1b}[31mc d\u{85}e\u{7f}")
        .build()
        .unwrap()
        .to_cef_string(Some("1"));
    assert!(cef.contains("suser=a b [31mc d e "), "{cef}");
    let separators = CefEvent::builder(E::SignInThrottled, TS).user("a\u{2028}b\u{2029}c\u{a0}d").build().unwrap();
    // The two separators are folded; a no-break space is not a control character and stays.
    assert!(separators.to_cef_string(None).contains("suser=a b c\u{a0}d"));
}

#[test]
fn the_header_escapes_a_pipe_and_folds_a_line_break_so_the_fields_cannot_shift() {
    assert_eq!(vectispire_domain::siem::cef::escape_header(Some("1.0|evil\\x\ny")), "1.0\\|evil\\\\x y");
    assert_eq!(vectispire_domain::siem::cef::escape_header(None), "");
}

#[test]
fn an_extension_key_that_is_not_alphanumeric_is_a_programming_error() {
    assert_eq!(
        CefEvent::at_type_severity(E::PingTest, TS, None, &[("a=b", "c")]).unwrap_err().0,
        "Not a CEF extension key: a=b"
    );
    assert!(CefEvent::builder(E::PingTest, TS).extension("with space", "v").build().is_err());
    // ASCII only, as Java's `[A-Za-z0-9]+` is: a Unicode letter or digit is not a key.
    assert!(CefEvent::builder(E::PingTest, TS).extension("é", "v").build().is_err());
    assert!(CefEvent::builder(E::PingTest, TS).extension("", "v").build().is_err());
    // An absent value is no field at all, and its key is never checked.
    assert!(CefEvent::builder(E::PingTest, TS).extension("with space", None).build().is_ok());
}

#[test]
fn a_field_given_twice_keeps_its_first_place_and_its_last_value_as_java_s_linked_hash_map() {
    let event = CefEvent::builder(E::PingTest, TS)
        .extension("cs1", "first")
        .user("alice")
        .target("second")
        .extension("rt", "overridden")
        .extension("msg", "early")
        .message("late")
        .build()
        .unwrap();
    assert_eq!(
        event.to_cef_string(Some("1")),
        "CEF:0|Vectispire|ASPM|1|VECTI-SEC-999|SIEM connector health check|1|rt=overridden outcome=success \
         cs1=second suser=alice cs1Label=Target msg=late"
    );
}

#[test]
fn a_blank_value_is_no_field_for_the_named_setters_and_a_field_for_extension() {
    let event = CefEvent::builder(E::PingTest, TS)
        .user(" ")
        .target("\t")
        .source_ip(None)
        .message("  ")
        .extension("cn1", "")
        .build()
        .unwrap();
    assert_eq!(
        event.to_cef_string(None),
        "CEF:0|Vectispire|ASPM||VECTI-SEC-999|SIEM connector health check|1|rt=1790416800000 outcome=success cn1="
    );
}

// --- SyslogMessageTest ---

fn event(kind: E) -> CefEvent {
    CefEvent::builder(kind, TS_MILLIS).build().unwrap()
}

#[test]
fn the_header_carries_priority_version_utc_timestamp_host_app_the_signature_as_msgid() {
    let message = syslog::format(&event(E::SignInThrottled), Some("vectispire-1"), "CEF:0|x");
    // Facility 10 × 8 + severity 3 (CEF 7 is "high", syslog "error") = 83.
    assert_eq!(message, "<83>1 2026-09-26T10:00:00.123Z vectispire-1 vectispire - VECTI-SEC-007 - CEF:0|x");
}

#[test]
fn the_priority_is_the_event_s_severity_not_its_type_s() {
    let breach = CefEvent::builder(E::SlaBreached, TS_MILLIS).issue_severity(Severity::Critical).build().unwrap();
    // CEF 8 → syslog 3: 80 + 3. At the type's 6 it would have been 84.
    assert!(syslog::format(&breach, Some("h"), "CEF").starts_with("<83>1 "));
}

#[test]
fn the_cef_band_decides_the_syslog_severity_and_nothing_pages_as_alert_or_emergency() {
    for (cef, expected) in [(10, 2), (9, 2), (8, 3), (7, 3), (6, 4), (4, 4), (3, 5), (1, 5), (0, 5)] {
        assert_eq!(syslog::syslog_severity(cef), expected, "CEF {cef}");
    }
    assert_eq!(syslog::priority(E::AuditChainBroken.cef_severity()), 82);
    assert_eq!(syslog::priority(E::PingTest.cef_severity()), 85);
}

#[test]
fn a_hostname_with_a_space_or_a_control_character_cannot_shift_the_header_s_fields() {
    assert!(
        syslog::format(&event(E::PingTest), Some("my host\n"), "CEF")
            .starts_with("<85>1 2026-09-26T10:00:00.123Z myhost vectispire - VECTI-SEC-999 - ")
    );
    assert!(syslog::format(&event(E::PingTest), Some(" "), "CEF").contains(".123Z - vectispire "));
    assert!(syslog::format(&event(E::PingTest), None, "CEF").contains(".123Z - vectispire "));
    // Printable US-ASCII only, at most 255 of it: an accented letter is dropped, not transliterated.
    assert!(syslog::format(&event(E::PingTest), Some("hôte"), "CEF").contains(".123Z hte vectispire "));
    let long = "h".repeat(300);
    assert!(
        syslog::format(&event(E::PingTest), Some(&long), "CEF")
            .contains(&format!(".123Z {} vectispire ", "h".repeat(255)))
    );
}

#[test]
fn no_byte_order_mark_cef_is_the_first_byte_of_msg() {
    let message = syslog::format(&event(E::PingTest), Some("h"), "CEF:0|Vectispire");
    assert!(!message.contains('\u{feff}'));
    assert!(message.ends_with(" - CEF:0|Vectispire"));
}

#[test]
fn octet_counting_counts_bytes_of_the_utf8_encoding_not_characters() {
    // "é" is two bytes: a character count would announce 4 and the receiver would cut the frame one byte short.
    let frame = syslog::octet_counted("café");
    assert_eq!(String::from_utf8(frame.clone()).unwrap(), "5 café");
    assert_eq!(frame.len(), 7);
}

#[test]
fn a_line_break_inside_the_message_does_not_end_the_frame() {
    assert_eq!(syslog::octet_counted("a\nb"), b"3 a\nb");
}

#[test]
fn the_timestamp_is_milliseconds_in_utc_truncated() {
    let at = Instant { epoch_second: 0, nano: 999_999_999 };
    assert!(
        syslog::format(&CefEvent::builder(E::PingTest, at).build().unwrap(), Some("h"), "x")
            .contains(" 1970-01-01T00:00:00.999Z ")
    );
}

// --- SiemEndpointTest ---

fn syslog_endpoint(protocol: SiemProtocol, host: &str, port: u16) -> SiemEndpoint {
    SiemEndpoint::Syslog { protocol, host: host.to_owned(), port }
}

fn refusal(protocol: SiemProtocol, value: &str) -> String {
    endpoint::parse(protocol, Some(value)).unwrap_err().0
}

#[test]
fn a_webhook_is_an_http_s_url() {
    assert_eq!(
        endpoint::parse(SiemProtocol::Webhook, Some(" https://siem.example.com/cef ")),
        Ok(SiemEndpoint::Webhook { url: "https://siem.example.com/cef".to_owned() })
    );
    let not_http = "A webhook endpoint is an http(s) URL, for example https://collector.example.com/cef.";
    assert_eq!(refusal(SiemProtocol::Webhook, "collector.example.com:514"), not_http);
    assert_eq!(refusal(SiemProtocol::Webhook, "ftp://x/"), not_http);
    assert!(endpoint::parse(SiemProtocol::Webhook, Some("HTTPS://siem.example.com/")).is_ok());
    assert_eq!(refusal(SiemProtocol::Webhook, "https://exa mple.com/"), "The webhook endpoint is not a readable URL.");
    // An authority that is not a server — an underscore is not a host character — has no host to the JDK.
    assert_eq!(refusal(SiemProtocol::Webhook, "https://exa_mple.com/"), "The webhook endpoint names no host.");
}

#[test]
fn a_syslog_endpoint_is_host_port_a_name_or_an_ipv4() {
    assert_eq!(
        endpoint::parse(SiemProtocol::SyslogTls, Some("collector.example.com:6514")),
        Ok(syslog_endpoint(SiemProtocol::SyslogTls, "collector.example.com", 6514))
    );
    assert_eq!(
        endpoint::parse(SiemProtocol::SyslogUdp, Some("10.0.0.5:514")),
        Ok(syslog_endpoint(SiemProtocol::SyslogUdp, "10.0.0.5", 514))
    );
    // A trailing dot is a fully qualified name, and a single label is a host too.
    assert!(endpoint::parse(SiemProtocol::SyslogTcp, Some("collector.:514")).is_ok());
    assert!(endpoint::parse(SiemProtocol::SyslogTcp, Some("collector:65535")).is_ok());
}

#[test]
fn a_webhook_s_port_is_one_a_connection_can_use() {
    assert!(endpoint::parse(SiemProtocol::Webhook, Some("https://siem.example.com:65535/cef")).is_ok());
    assert!(endpoint::parse(SiemProtocol::Webhook, Some("https://siem.example.com:1/cef")).is_ok());
    for value in
        ["https://siem.example.com:99999/cef", "https://siem.example.com:0/cef", "https://siem.example.com:65536/"]
    {
        assert_eq!(
            refusal(SiemProtocol::Webhook, value),
            "The webhook endpoint's port must be a number between 1 and 65535.",
            "{value}"
        );
    }
    // Past an `int`, `URI` reads no port at all: a registry authority, with no host.
    assert_eq!(
        refusal(SiemProtocol::Webhook, "https://siem.example.com:2147483648/cef"),
        "The webhook endpoint names no host."
    );
}

#[test]
fn a_numeric_host_is_what_the_resolver_reads_as_an_address() {
    for value in ["10.1:514", "010.0.0.1:514", "16909060:514", "1.2.3.4.:514", "255.255.255.255:514", "1.2.65535:514"] {
        assert!(endpoint::parse(SiemProtocol::SyslogUdp, Some(value)).is_ok(), "{value} was refused");
    }
    for value in [
        "999.999.999.999:514",
        "256.0.0.1:514",
        "1.2.3.4.5:514",
        "1.2.3.4..:514",
        "4294967296:514",
        "1.2.65536:514",
        "0000000000000001:514",
    ] {
        assert!(
            refusal(SiemProtocol::SyslogUdp, value).ends_with("is not a host name or an IPv4 address."),
            "{value} was accepted"
        );
    }
    // A host with a letter is a name, whatever digits it holds: the resolver asks DNS for it.
    assert!(endpoint::parse(SiemProtocol::SyslogUdp, Some("4294967296a:514")).is_ok());
}

#[test]
fn a_port_written_with_leading_zeros_is_that_port_so_a_stored_one_keeps_working() {
    assert_eq!(
        endpoint::parse(SiemProtocol::SyslogTcp, Some("collector.example.com:00514")),
        Ok(syslog_endpoint(SiemProtocol::SyslogTcp, "collector.example.com", 514))
    );
}

#[test]
fn an_ipv6_collector_is_written_in_brackets_which_are_not_part_of_the_host() {
    assert_eq!(
        endpoint::parse(SiemProtocol::SyslogTcp, Some("[2001:db8::1]:514")),
        Ok(syslog_endpoint(SiemProtocol::SyslogTcp, "2001:db8::1", 514))
    );
    assert!(refusal(SiemProtocol::SyslogTcp, "2001:db8::1:514").contains("[address]:port"));
    assert!(refusal(SiemProtocol::SyslogTcp, "[not-v6]:514").contains("not an IPv6 address"));
    // The JDK reads an IPv4-mapped address as the IPv4 address it maps: not an IPv6 literal.
    assert_eq!(
        refusal(SiemProtocol::SyslogTcp, "[::ffff:10.0.0.1]:514"),
        "\"::ffff:10.0.0.1\" is not an IPv6 address."
    );
    assert!(endpoint::parse(SiemProtocol::SyslogTcp, Some("[::10.0.0.1]:514")).is_ok());
    // A numeric scope is accepted; an interface's name depends on the machine and is refused everywhere.
    assert!(endpoint::parse(SiemProtocol::SyslogTcp, Some("[fe80::1%2]:514")).is_ok());
    assert!(endpoint::parse(SiemProtocol::SyslogTcp, Some("[fe80::1%eth0]:514")).is_err());
    assert!(endpoint::parse(SiemProtocol::SyslogTcp, Some("[fe80::1%99999999999]:514")).is_err());
    assert_eq!(refusal(SiemProtocol::SyslogTcp, "[::1]"), "An IPv6 syslog endpoint is written [address]:port.");
    assert_eq!(refusal(SiemProtocol::SyslogTcp, "[::1]x:514"), "An IPv6 syslog endpoint is written [address]:port.");
    assert_eq!(refusal(SiemProtocol::SyslogTcp, "[::1"), "An IPv6 syslog endpoint is written [address]:port.");
}

#[test]
fn refuses_malformed_syslog() {
    for value in [
        "syslog+tls://collector.example.com:6514",
        "tcp://collector:514",
        "collector.example.com",
        "collector.example.com:",
        "collector.example.com:0",
        "collector.example.com:65536",
        "collector.example.com:５１４",
        "collector.example.com:514/path",
        ":514",
        "bad_host!:514",
        "host name:514",
        // A label of 64 characters, one more than DNS allows; a label ending on a hyphen.
        &format!("{}.example.com:514", "a".repeat(64)),
        "collector-.example.com:514",
        "a..b:514",
        // The Kelvin sign is not a `k` to Java's ASCII-only `(?i)`.
        "\u{212a}ollector:514",
    ] {
        assert!(endpoint::parse(SiemProtocol::SyslogTls, Some(value)).is_err(), "{value:?} was accepted");
    }
}

#[test]
fn the_syslog_refusals_are_java_s_sentences() {
    assert_eq!(
        refusal(SiemProtocol::SyslogTls, "syslog+tls://collector.example.com:6514"),
        "A syslog endpoint is host:port, for example collector.example.com:6514 — no scheme and no path: the protocol \
         field already says how events travel."
    );
    assert_eq!(
        refusal(SiemProtocol::SyslogUdp, "collector.example.com"),
        "A syslog endpoint needs its port, for example collector.example.com:514."
    );
    assert_eq!(
        refusal(SiemProtocol::SyslogTcp, "bad_host!:514"),
        "\"bad_host!\" is not a host name or an IPv4 address."
    );
    assert_eq!(refusal(SiemProtocol::SyslogTcp, ":514"), "\"\" is not a host name or an IPv4 address.");
    assert_eq!(refusal(SiemProtocol::SyslogTcp, "c:0"), "The port must be a number between 1 and 65535.");
    assert_eq!(refusal(SiemProtocol::SyslogTcp, "c:123456"), "The port must be a number between 1 and 65535.");
}

#[test]
fn an_empty_endpoint_is_refused_for_every_protocol() {
    for protocol in SiemProtocol::ALL {
        assert_eq!(endpoint::parse(protocol, Some("  ")).unwrap_err().0, "The endpoint is required.");
        assert_eq!(endpoint::parse(protocol, None).unwrap_err().0, "The endpoint is required.");
    }
}

#[test]
fn a_protocol_is_named_case_aside_and_only_a_webhook_carries_headers() {
    assert_eq!(SiemProtocol::by_name(Some(" syslog_tls ")), Some(SiemProtocol::SyslogTls));
    assert_eq!(SiemProtocol::by_name(Some("Webhook")), Some(SiemProtocol::Webhook));
    // `toUpperCase(Locale.ROOT)` makes the long s an S.
    assert_eq!(SiemProtocol::by_name(Some("\u{17f}yslog_udp")), Some(SiemProtocol::SyslogUdp));
    assert_eq!(SiemProtocol::by_name(Some("syslog")), None);
    assert_eq!(SiemProtocol::by_name(None), None);
    let carrying: Vec<SiemProtocol> = SiemProtocol::ALL.into_iter().filter(|p| p.carries_headers()).collect();
    assert_eq!(carrying, [SiemProtocol::Webhook]);
}

// --- SecurityEventTypeTest ---

#[test]
fn the_signature_identifiers_are_the_contract_a_soc_s_rules_are_written_against() {
    // Changing one of these silently disarms every correlation rule written against it, in somebody else's SIEM.
    // A change here has to be a decision, made in this file on purpose.
    let expected = [
        ("CRITICAL_KEV_DETECTED", "VECTI-SEC-002"),
        ("SECURITY_GATE_FAILED", "VECTI-SEC-003"),
        ("TRIAGE_SETTLED", "VECTI-SEC-005"),
        ("MFA_BACKUP_CODE_USED", "VECTI-SEC-006"),
        ("SIGN_IN_THROTTLED", "VECTI-SEC-007"),
        ("MFA_FAILURE_CEILING", "VECTI-SEC-008"),
        ("BEARER_TOKEN_THROTTLED", "VECTI-SEC-009"),
        ("ACCOUNT_CHANGED", "VECTI-SEC-010"),
        ("ACCESS_GRANT_CHANGED", "VECTI-SEC-011"),
        ("API_KEY_ISSUED", "VECTI-SEC-012"),
        ("API_KEY_REVOKED", "VECTI-SEC-013"),
        ("AGENT_CHANGED", "VECTI-SEC-014"),
        ("AGENT_RESULT_REFUSED", "VECTI-SEC-015"),
        ("TRIAGE_APPROVED", "VECTI-SEC-016"),
        ("TRIAGE_REFUSED", "VECTI-SEC-017"),
        ("AUDIT_CHAIN_BROKEN", "VECTI-SEC-018"),
        ("SECURITY_SETTING_CHANGED", "VECTI-SEC-019"),
        ("AGENT_SEALING_KEY_REFUSED", "VECTI-SEC-020"),
        ("PLUGIN_CHANGED", "VECTI-SEC-021"),
        ("SARIF_SOURCE_CHANGED", "VECTI-SEC-022"),
        ("SARIF_IMPORT_REFUSED", "VECTI-SEC-023"),
        ("CHECKLIST_TEMPLATE_CHANGED", "VECTI-SEC-024"),
        ("CHECKLIST_SIGNED_OFF", "VECTI-SEC-025"),
        ("CHECKLIST_SIGN_OFF_REFUSED", "VECTI-SEC-026"),
        ("REPORT_IMPORT_REFUSED", "VECTI-SEC-027"),
        ("SIEM_EXPORT_STOPPED", "VECTI-SEC-028"),
        ("SECRET_LEAK_DETECTED", "VECTI-SEC-029"),
        ("SLA_BREACHED", "VECTI-SEC-030"),
        ("REPORT_PLUGIN_CHANGED", "VECTI-SEC-031"),
        ("PROJECT_EXPORTED", "VECTI-SEC-032"),
        ("REPORT_PLUGIN_REFUSED", "VECTI-SEC-033"),
        ("FORGE_CONNECTION_CHANGED", "VECTI-SEC-034"),
        ("FORGE_IMPORT_APPLIED", "VECTI-SEC-035"),
        ("FORGE_CONNECTION_REFUSED", "VECTI-SEC-036"),
        ("TRACKER_CONTRADICTS_TRIAGE", "VECTI-SEC-037"),
        ("INTEGRATION_TOKEN_EXPIRING", "VECTI-SEC-038"),
        ("INTEGRATION_TOKEN_STOPPED", "VECTI-SEC-039"),
        ("INTEGRATION_TOKEN_RESTORED", "VECTI-SEC-040"),
        ("PING_TEST", "VECTI-SEC-999"),
    ];
    let actual: Vec<(&str, &str)> = E::ALL.iter().map(|kind| (kind.wire_name(), kind.signature_id())).collect();
    assert_eq!(actual, expected);
    for kind in E::ALL {
        assert_eq!(E::from_wire_name(kind.wire_name()), Some(*kind));
    }
    assert_eq!(E::from_wire_name("ping_test"), None, "valueOf is exact");
}

#[test]
fn thirty_three_is_the_report_plugins_refusal_signalled_by_report_refused_alone() {
    assert_eq!(signalled_by("REPORT_REFUSED"), Some(E::ReportPluginRefused));
    assert_eq!(E::ReportPluginRefused.cef_severity(), 6);
    assert_eq!(signalled_by("REPORT_FAILED"), None);
    assert_eq!(signalled_by("REPORT_REQUESTED"), None);
    assert_eq!(signalled_by("REPORT_PRODUCED"), None);
}

#[test]
fn thirty_five_is_the_import_from_a_forge_named_by_its_writer() {
    assert_eq!(E::ForgeImportApplied.signature_id(), "VECTI-SEC-035");
    assert_eq!(E::ForgeImportApplied.cef_severity(), 5);
    assert_eq!(E::ForgeImportApplied.outcome(), Outcome::Success);
    assert_eq!(signalled_by("FORGE_IMPORT_APPLIED"), None);
}

#[test]
fn thirty_eight_to_forty_are_an_integration_token_s_change_of_state() {
    assert_eq!(signalled_by("INTEGRATION_TOKEN_EXPIRING"), Some(E::IntegrationTokenExpiring));
    assert_eq!(signalled_by("INTEGRATION_TOKEN_STOPPED"), Some(E::IntegrationTokenStopped));
    assert_eq!(signalled_by("INTEGRATION_TOKEN_RESTORED"), Some(E::IntegrationTokenRestored));
    assert_eq!(E::IntegrationTokenExpiring.cef_severity(), 4);
    assert_eq!(E::IntegrationTokenStopped.cef_severity(), 7);
    assert_eq!(E::IntegrationTokenRestored.cef_severity(), 2);
    assert_eq!(E::IntegrationTokenStopped.outcome(), Outcome::Failure);
}

#[test]
fn no_identifier_is_used_twice_and_the_two_retired_ones_are_never_reused() {
    let identifiers: HashSet<&str> = E::ALL.iter().map(|kind| kind.signature_id()).collect();
    assert_eq!(identifiers.len(), E::ALL.len());
    assert!(!identifiers.contains("VECTI-SEC-001") && !identifiers.contains("VECTI-SEC-004"));
}

#[test]
fn every_severity_is_a_cef_severity() {
    assert!(E::ALL.iter().all(|kind| kind.cef_severity() <= 10));
}

#[test]
fn an_issue_s_severity_as_an_event_s_cef_severity() {
    for (issue, cef) in [
        (Severity::Critical, 8),
        (Severity::High, 7),
        (Severity::Medium, 5),
        (Severity::Low, 3),
        (Severity::Negligible, 3),
        (Severity::Unknown, 3),
    ] {
        assert_eq!(E::cef_severity_of(issue), cef, "{issue:?}");
    }
}

#[test]
fn only_the_deadline_breach_follows_its_issue_s_severity() {
    let following: Vec<E> = E::ALL.iter().copied().filter(|kind| kind.follows_issue_severity()).collect();
    assert_eq!(following, [E::SlaBreached]);
}

#[test]
fn the_unambiguous_audit_operations_signal_their_event_on_their_own() {
    for (operation, kind) in [
        ("API_KEY_CREATED", E::ApiKeyIssued),
        ("API_KEY_DELETED", E::ApiKeyRevoked),
        ("TEAM_ACCESS_CHANGED", E::AccessGrantChanged),
        ("USER_UPDATED", E::AccountChanged),
        ("PROJECT_REPOSITORIES_CHANGED", E::AccessGrantChanged),
        ("PROJECT_CONTAINERS_CHANGED", E::AccessGrantChanged),
        ("AGENT_UPDATED", E::AgentChanged),
        ("AGENT_SIGNING_KEY_PINNED", E::AgentChanged),
        ("AGENT_SEALING_KEY_RESET", E::AgentChanged),
        ("AGENT_SEALING_KEY_REFUSED", E::AgentSealingKeyRefused),
        ("GATE_POLICY_UPDATED", E::SecuritySettingChanged),
        ("PLUGIN_REGISTERED", E::PluginChanged),
        ("PLUGIN_ACTIVATED", E::PluginChanged),
        // Running a plugin nobody vouched for is a change to what reads the source, like the others.
        ("PLUGIN_SIGNATURE_WAIVED", E::PluginChanged),
        ("PLUGIN_SIGNATURE_WAIVER_REVOKED", E::PluginChanged),
        ("SARIF_SOURCE_CHANGED", E::SarifSourceChanged),
        ("SARIF_IMPORT_REFUSED", E::SarifImportRefused),
        // A project's whole state leaving the platform is what a SOC wants to see, every time (decision 0035).
        ("PROJECT_EXPORTED", E::ProjectExported),
        ("REPORT_PLUGIN_REGISTERED", E::ReportPluginChanged),
        ("REPORT_PLUGIN_UPDATED", E::ReportPluginChanged),
        ("REPORT_PLUGIN_APPROVED", E::ReportPluginChanged),
        ("REPORT_PLUGIN_ENABLED_CHANGED", E::ReportPluginChanged),
        ("REPORT_PLUGIN_ACTIVATED", E::ReportPluginChanged),
        ("REPORT_PLUGIN_DEACTIVATED", E::ReportPluginChanged),
        ("REPORT_PLUGIN_WITHDRAWN", E::ReportPluginChanged),
        ("FORGE_CONNECTION_REFUSED", E::ForgeConnectionRefused),
        ("TRIAGE_CONTRADICTED_BY_TRACKER", E::TrackerContradictsTriage),
        ("REPORT_IMPORT_REFUSED", E::ReportImportRefused),
        ("CHECKLIST_TEMPLATE_PUBLISHED", E::ChecklistTemplateChanged),
        ("CHECKLIST_SIGNED_OFF", E::ChecklistSignedOff),
        ("CHECKLIST_SIGN_OFF_REFUSED", E::ChecklistSignOffRefused),
        ("CHECKLIST_RETURNED", E::ChecklistSignOffRefused),
    ] {
        assert_eq!(signalled_by(operation), Some(kind), "{operation}");
    }
    for quiet in [
        "PROJECT_UPDATED",
        // A rotation happens at every start of every agent: routine, not an event for a SOC.
        "AGENT_SEALING_KEY_ACCEPTED",
        // A pipeline's upload is as frequent as its builds: the entry, not an event.
        "SARIF_IMPORTED",
        "COVERAGE_IMPORTED",
        "TEST_REPORT_IMPORTED",
        // A draft being written changes nothing any project attests to.
        "CHECKLIST_TEMPLATE_IMPORTED",
        "CHECKLIST_TEMPLATE_LAYOUT_CONFIRMED",
        "CHECKLIST_TEMPLATE_ITEMS_PAIRED",
        "CHECKLIST_TEMPLATE_DERIVED",
        // Filling a checklist is work, not a security event.
        "CHECKLIST_OPENED",
        "CHECKLIST_MOVED_TO_VERSION",
        "CHECKLIST_ANSWERED",
        "CHECKLIST_EVIDENCE_ADDED",
        "CHECKLIST_EVIDENCE_WITHDRAWN",
        "CHECKLIST_SUBMITTED",
        "CHECKLIST_REOPENED",
    ] {
        assert_eq!(event_type::placement(quiet), Some(Placement::Quiet), "{quiet}");
    }
}

#[test]
fn the_ambiguous_ones_signal_nothing_by_themselves_their_writers_name_the_event() {
    // LOGIN_BLOCKED is also "password sign-in is disabled"; SETTING_UPDATED is also a branch name; ISSUE_TRIAGED
    // is also a ticket link. Mapped by operation, each would flood a SOC.
    for quiet in [
        "LOGIN_BLOCKED",
        "SETTING_UPDATED",
        "ISSUE_TRIAGED",
        "ACCESS_DENIED",
        "LOGIN_SUCCESS",
        "CHECKLIST_TEMPLATE_RETIRED",
        "FORGE_CONNECTION_CHANGED",
    ] {
        assert_eq!(event_type::placement(quiet), Some(Placement::Quiet), "{quiet}");
    }
    // A name that is no operation is placed nowhere — Java's `signalledBy(null)`.
    assert_eq!(event_type::placement("NOT_AN_OPERATION"), None);
    assert_eq!(signalled_by(""), None);
}

#[test]
fn no_operation_is_placed_twice() {
    let signalling: HashSet<&str> = event_type::SIGNALLING.iter().map(|(name, _)| *name).collect();
    assert_eq!(signalling.len(), event_type::SIGNALLING.len());
    let quiet: HashSet<&str> = event_type::QUIET.iter().copied().collect();
    assert_eq!(quiet.len(), event_type::QUIET.len());
    assert!(signalling.is_disjoint(&quiet));
}

// --- SiemSeverityFilterTest ---

fn admits(kind: E, stored: Option<&str>) -> bool {
    severity_filter::admits(&CefEvent::builder(kind, Instant::of_epoch_second(0)).build().unwrap(), stored)
}

fn breach_of(severity: Severity) -> CefEvent {
    CefEvent::builder(E::SlaBreached, Instant::of_epoch_second(0)).issue_severity(severity).build().unwrap()
}

#[test]
fn critical_forwards_the_very_high_band_only() {
    assert!(admits(E::AuditChainBroken, Some("CRITICAL")));
    assert!(admits(E::CriticalKevDetected, Some("CRITICAL")));
    assert!(!admits(E::AgentResultRefused, Some("CRITICAL")));
    assert!(!admits(E::SignInThrottled, Some("CRITICAL")));
}

#[test]
fn high_forwards_seven_and_above_and_not_a_medium() {
    assert!(admits(E::SignInThrottled, Some("HIGH")));
    assert!(admits(E::SecurityGateFailed, Some("HIGH")));
    assert!(!admits(E::AccountChanged, Some("HIGH")));
    assert!(!admits(E::ApiKeyRevoked, Some("HIGH")));
}

#[test]
fn medium_forwards_four_and_above_low_everything() {
    assert!(admits(E::ApiKeyRevoked, Some("MEDIUM")));
    assert!(admits(E::ApiKeyRevoked, Some("medium")));
    assert!(admits(E::ApiKeyRevoked, Some(" Medium\t")));
    assert!(admits(E::ApiKeyRevoked, Some("LOW")));
    assert!(!admits(E::IntegrationTokenRestored, Some("MEDIUM")));
}

#[test]
fn no_or_an_unreadable_threshold_sends_everything() {
    // Silence nobody sees is the failure not worth having in a security feed.
    for stored in [None, Some(""), Some("   "), Some("SEVERE"), Some("UNKNOWN"), Some("NEGLIGIBLE")] {
        for kind in E::ALL {
            assert!(admits(*kind, stored), "{kind:?} under {stored:?}");
        }
    }
}

#[test]
fn the_connection_test_goes_through_whatever_the_threshold() {
    assert!(admits(E::PingTest, Some("CRITICAL")));
}

#[test]
fn at_the_factory_minimum_a_critical_or_high_issue_s_breach_is_forwarded_a_medium_or_low_one_s_is_not() {
    assert!(severity_filter::admits(&breach_of(Severity::Critical), Some("HIGH")));
    assert!(severity_filter::admits(&breach_of(Severity::High), Some("HIGH")));
    assert!(!severity_filter::admits(&breach_of(Severity::Medium), Some("HIGH")));
    assert!(!severity_filter::admits(&breach_of(Severity::Low), Some("HIGH")));
}

#[test]
fn medium_lets_a_medium_issue_s_breach_through_and_still_not_a_low_one_s() {
    assert!(severity_filter::admits(&breach_of(Severity::Medium), Some("MEDIUM")));
    assert!(!severity_filter::admits(&breach_of(Severity::Low), Some("MEDIUM")));
    assert!(severity_filter::admits(&breach_of(Severity::Low), Some("LOW")));
}

// --- TriageSignalsTest ---

#[test]
fn settling_directly_not_affected_or_fixed_is_a_settled_finding() {
    assert_eq!(triage_signals::of(&[Some("under_review")], Some("not_affected")), Some(E::TriageSettled));
    assert_eq!(triage_signals::of(&[None], Some("fixed")), Some(E::TriageSettled));
    assert_eq!(triage_signals::of(&[Some("affected")], Some("will_not_fix")), Some(E::TriageSettled));
}

#[test]
fn settling_a_pending_request_is_an_approval() {
    assert_eq!(triage_signals::of(&[Some("pending_approval")], Some("not_affected")), Some(E::TriageApproved));
    // In a bulk decision one request among the selection is enough to make it an answer.
    assert_eq!(
        triage_signals::of(&[Some("affected"), Some("pending_approval")], Some("fixed")),
        Some(E::TriageApproved)
    );
}

#[test]
fn sending_a_pending_request_back_is_a_refusal() {
    assert_eq!(triage_signals::of(&[Some("pending_approval")], Some("under_review")), Some(E::TriageRefused));
    assert_eq!(triage_signals::of(&[Some("pending_approval")], Some("affected")), Some(E::TriageRefused));
}

#[test]
fn housekeeping_and_requests_are_not_forwarded() {
    assert_eq!(triage_signals::of(&[Some("affected")], Some("under_review")), None);
    // A dismissal by somebody who cannot approve lands as a request: the control working.
    assert_eq!(triage_signals::of(&[Some("under_review")], Some("pending_approval")), None);
    assert_eq!(triage_signals::of(&[Some("pending_approval")], Some("pending_approval")), None);
    assert_eq!(triage_signals::of(&[Some("under_review")], Some("a_status_from_the_future")), None);
    assert_eq!(triage_signals::of(&[Some("pending_approval")], None), None);
}

// --- SecurityEventCatalogueDocsTest ---

/// The catalogue a SOC writes its rules from is the one the code emits: both pages of the guide list exactly the
/// emitted identifiers, with the CEF `Name` and the severity — a range (`3–8`) for a type that follows its issue.
#[test]
fn the_guide_lists_exactly_what_is_emitted() {
    let pattern = regex::Regex::new(r"(?m)^\| `(VECTI-SEC-\d{3})` \| ([^|]+) \| (\d+(?:–\d+)?) \|").unwrap();
    let span = {
        let all = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Negligible,
            Severity::Unknown,
        ];
        let values: Vec<u8> = all.into_iter().map(E::cef_severity_of).collect();
        format!("{}–{}", values.iter().min().unwrap(), values.iter().max().unwrap())
    };
    let mut emitted: Vec<(String, String, String)> = E::ALL
        .iter()
        .map(|kind| {
            let severity = if kind.follows_issue_severity() { span.clone() } else { kind.cef_severity().to_string() };
            (kind.signature_id().to_owned(), kind.description().to_owned(), severity)
        })
        .collect();
    emitted.sort();
    for page in ["siem.md", "siem.fr.md"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs-site/integrations").join(page);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let mut documented: Vec<(String, String, String)> = pattern
            .captures_iter(&text)
            .map(|row| (row[1].to_owned(), row[2].trim().to_owned(), row[3].to_owned()))
            .collect();
        documented.sort();
        assert_eq!(documented, emitted, "{page}");
    }
}

package com.asmolabs.vectispire.common.domain.siem;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RFC 5424 framing of a CEF event, and RFC 6587 octet counting")
class SyslogMessageTest {

    private static final Instant TS = Instant.parse("2026-09-26T10:00:00.123Z");

    @Test
    @DisplayName("the header carries priority, version, UTC timestamp, host, app, the signature as MSGID")
    void header() {
        String message = SyslogMessage.format(event(SecurityEventType.SIGN_IN_THROTTLED), "vectispire-1", "CEF:0|x");

        // Facility 10 × 8 + severity 3 (CEF 7 is "high", syslog "error") = 83.
        assertThat(message).isEqualTo("<83>1 2026-09-26T10:00:00.123Z vectispire-1 vectispire - VECTI-SEC-007 - CEF:0|x");
    }

    @Test
    @DisplayName("the priority is the event's severity, not its type's: a critical issue's breach is an error, not a warning")
    void priorityFollowsTheEvent() {
        CefEvent breach = CefEvent.builder(SecurityEventType.SLA_BREACHED)
                .issueSeverity(Severity.CRITICAL)
                .timestamp(TS)
                .build();

        // CEF 8 → syslog 3: 80 + 3. At the type's 6 it would have been 84.
        assertThat(SyslogMessage.format(breach, "h", "CEF")).startsWith("<83>1 ");
    }

    @Test
    @DisplayName("the CEF band decides the syslog severity, and nothing pages as alert or emergency")
    void severityBands() {
        assertThat(SyslogMessage.syslogSeverity(10)).isEqualTo(2);
        assertThat(SyslogMessage.syslogSeverity(9)).isEqualTo(2);
        assertThat(SyslogMessage.syslogSeverity(8)).isEqualTo(3);
        assertThat(SyslogMessage.syslogSeverity(7)).isEqualTo(3);
        assertThat(SyslogMessage.syslogSeverity(6)).isEqualTo(4);
        assertThat(SyslogMessage.syslogSeverity(4)).isEqualTo(4);
        assertThat(SyslogMessage.syslogSeverity(3)).isEqualTo(5);
        assertThat(SyslogMessage.syslogSeverity(1)).isEqualTo(5);
        assertThat(SyslogMessage.priority(SecurityEventType.AUDIT_CHAIN_BROKEN.cefSeverity())).isEqualTo(82);
        assertThat(SyslogMessage.priority(SecurityEventType.PING_TEST.cefSeverity())).isEqualTo(85);
    }

    @Test
    @DisplayName("a hostname with a space or a control character cannot shift the header's fields")
    void hostnameIsAToken() {
        assertThat(SyslogMessage.format(event(SecurityEventType.PING_TEST), "my host\n", "CEF"))
                .startsWith("<85>1 2026-09-26T10:00:00.123Z myhost vectispire - VECTI-SEC-999 - ");
        assertThat(SyslogMessage.format(event(SecurityEventType.PING_TEST), " ", "CEF"))
                .contains(".123Z - vectispire ");
        assertThat(SyslogMessage.format(event(SecurityEventType.PING_TEST), null, "CEF"))
                .contains(".123Z - vectispire ");
    }

    @Test
    @DisplayName("no byte-order mark: CEF:0| is the first byte of MSG")
    void noBom() {
        String message = SyslogMessage.format(event(SecurityEventType.PING_TEST), "h", "CEF:0|Vectispire");

        assertThat(message).doesNotContain("﻿").endsWith(" - CEF:0|Vectispire");
    }

    @Test
    @DisplayName("octet counting counts bytes of the UTF-8 encoding, not characters")
    void octetCounting() {
        // "é" is two bytes: a character count would announce 4 and the receiver would cut the
        // frame one byte short, then read the leftover as the start of the next one.
        byte[] frame = SyslogMessage.octetCounted("café");

        assertThat(new String(frame, StandardCharsets.UTF_8)).isEqualTo("5 café");
        assertThat(frame).hasSize(7);
    }

    @Test
    @DisplayName("a line break inside the message does not end the frame")
    void framingDoesNotDependOnNewlines() {
        byte[] frame = SyslogMessage.octetCounted("a\nb");

        assertThat(new String(frame, StandardCharsets.UTF_8)).isEqualTo("3 a\nb");
    }

    private static CefEvent event(SecurityEventType type) {
        return CefEvent.builder(type).timestamp(TS).build();
    }
}

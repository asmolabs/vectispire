package com.asmolabs.vectispire.common.domain.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CefEvent formatting according to the ArcSight CEF specification")
class CefEventTest {

    private static final Instant TS = Instant.parse("2026-09-26T10:00:00Z");

    @Test
    @DisplayName("formats the header and the standard extension fields")
    void formatsHeaderAndFields() {
        CefEvent event = CefEvent.builder(SecurityEventType.API_KEY_ISSUED)
                .timestamp(TS)
                .message("API key issued: ci-pipeline")
                .user("alice")
                .sourceIp("203.0.113.7")
                .action("API_KEY_CREATED")
                .target("42")
                .build();

        String cef = event.toCefString("2.3.0");

        assertThat(cef).startsWith("CEF:0|Vectispire|ASPM|2.3.0|ZAN-SEC-012|API key issued|5|");
        assertThat(cef).contains("rt=" + TS.toEpochMilli());
        assertThat(cef).contains("outcome=success");
        assertThat(cef).contains("suser=alice");
        assertThat(cef).contains("src=203.0.113.7");
        assertThat(cef).contains("act=API_KEY_CREATED");
        assertThat(cef).contains("cs1Label=Target cs1=42");
        assertThat(cef).endsWith("msg=API key issued: ci-pipeline");
    }

    @Test
    @DisplayName("an unknown product version leaves the field empty rather than inventing one")
    void noVersionIsAnEmptyField() {
        String cef = CefEvent.builder(SecurityEventType.PING_TEST).timestamp(TS).build().toCefString(null);

        assertThat(cef).startsWith("CEF:0|Vectispire|ASPM||ZAN-SEC-999|");
    }

    @Test
    @DisplayName("escapes backslash and equals in extension values, and leaves a pipe alone there")
    void escapesExtensionValues() {
        CefEvent event = CefEvent.builder(SecurityEventType.SECURITY_GATE_FAILED)
                .timestamp(TS)
                .message("Policy failed: Rule|A=B \\ end")
                .build();

        assertThat(event.toCefString("1")).contains("msg=Policy failed: Rule|A\\=B \\\\ end");
    }

    @Test
    @DisplayName("an attacker-chosen username cannot forge a second event or a new field")
    void aUsernameCannotInjectAnEvent() {
        // Typed into the sign-in form, recorded as the audit entry's user, forwarded as suser.
        String typed = "mallory\nCEF:0|Vectispire|ASPM|1|ZAN-SEC-018|forged|10|suser=admin\r\nsrc=1.2.3.4 act=x";

        String cef = CefEvent.builder(SecurityEventType.SIGN_IN_THROTTLED).timestamp(TS).user(typed).build()
                .toCefString("1");

        // One line, whatever the collector splits on.
        assertThat(cef).doesNotContain("\n").doesNotContain("\r");
        // The equals signs are escaped, so no parser reads "src=" or "suser=" as a field of ours.
        assertThat(cef).contains("suser=mallory\\nCEF:0|Vectispire|ASPM|1|ZAN-SEC-018|forged|10|suser\\=admin\\r\\nsrc\\=1.2.3.4 act\\=x");
        // Exactly one unescaped "suser=" and no unescaped "src=".
        assertThat(cef.split("(?<!\\\\)suser=", -1)).hasSize(2);
        assertThat(cef).doesNotContainPattern("(?<!\\\\)src=");
    }

    @Test
    @DisplayName("control characters and Unicode line separators become spaces")
    void controlCharactersAreNeutralized() {
        String cef = CefEvent.builder(SecurityEventType.SIGN_IN_THROTTLED).timestamp(TS)
                .user("a\u0000b\u001b[31mc d\u0085e\u007f")
                .build()
                .toCefString("1");

        assertThat(cef).contains("suser=a b [31mc d e ");
    }

    @Test
    @DisplayName("the header escapes a pipe and folds a line break, so the fields cannot shift")
    void headerIsEscaped() {
        assertThat(CefEvent.escapeHeader("1.0|evil\\x\ny")).isEqualTo("1.0\\|evil\\\\x y");
    }

    @Test
    @DisplayName("an extension key that is not alphanumeric is a programming error")
    void badKeysAreRefused() {
        assertThatThrownBy(() -> new CefEvent(SecurityEventType.PING_TEST, TS, null, Map.of("a=b", "c")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> CefEvent.builder(SecurityEventType.PING_TEST).extension("with space", "v").build())
                .isInstanceOf(IllegalArgumentException.class);
    }
}

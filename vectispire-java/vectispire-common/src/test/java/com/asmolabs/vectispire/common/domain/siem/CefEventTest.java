package com.asmolabs.zanshin.common.domain.siem;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CefEvent formatting according to ArcSight CEF v0.1 specification")
class CefEventTest {

    @Test
    @DisplayName("formats a secret leak security event to valid CEF string")
    void formatsSecretLeakCef() {
        Instant ts = Instant.parse("2026-08-22T10:00:00Z");
        CefEvent event = CefEvent.builder(SecurityEventType.SECRET_LEAK_DETECTED)
                .timestamp(ts)
                .message("AWS secret key committed in main branch")
                .target("https://github.com/asmolabs/billing.git")
                .assetTier("TIER_1_MISSION_CRITICAL")
                .identifier("AWS-ACCESS-KEY")
                .user("alice")
                .build();

        String cef = event.toCefString();

        assertThat(cef).startsWith("CEF:0|Zanshin|ASPM|1.0|ZAN-SEC-001|Secret Leak Detected|10|");
        assertThat(cef).contains("suser=alice");
        assertThat(cef).contains("cs1Label=Target cs1=https://github.com/asmolabs/billing.git");
        assertThat(cef).contains("cs2Label=AssetTier cs2=TIER_1_MISSION_CRITICAL");
        assertThat(cef).contains("cs3Label=Identifier cs3=AWS-ACCESS-KEY");
        assertThat(cef).contains("msg=AWS secret key committed in main branch");
        assertThat(cef).contains("rt=" + ts.toEpochMilli());
    }

    @Test
    @DisplayName("escapes pipe and equals signs properly")
    void escapesSpecialCharacters() {
        CefEvent event = CefEvent.builder(SecurityEventType.SECURITY_GATE_FAILED)
                .message("Policy failed: Rule|A=B")
                .build();

        String cef = event.toCefString();
        assertThat(cef).contains("msg=Policy failed: Rule|A\\=B");
    }
}

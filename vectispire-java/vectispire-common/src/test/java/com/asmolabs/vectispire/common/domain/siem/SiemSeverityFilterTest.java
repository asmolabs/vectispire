package com.asmolabs.vectispire.common.domain.siem;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("the SIEM minimum severity")
class SiemSeverityFilterTest {

    @Test
    @DisplayName("CRITICAL forwards the very-high band only")
    void critical() {
        assertThat(SiemSeverityFilter.admits(SecurityEventType.AUDIT_CHAIN_BROKEN, "CRITICAL")).isTrue();
        assertThat(SiemSeverityFilter.admits(SecurityEventType.CRITICAL_KEV_DETECTED, "CRITICAL")).isTrue();
        assertThat(SiemSeverityFilter.admits(SecurityEventType.AGENT_RESULT_REFUSED, "CRITICAL")).isFalse();
        assertThat(SiemSeverityFilter.admits(SecurityEventType.SIGN_IN_THROTTLED, "CRITICAL")).isFalse();
    }

    @Test
    @DisplayName("HIGH forwards 7 and above, and not a medium")
    void high() {
        assertThat(SiemSeverityFilter.admits(SecurityEventType.SIGN_IN_THROTTLED, "HIGH")).isTrue();
        assertThat(SiemSeverityFilter.admits(SecurityEventType.SECURITY_GATE_FAILED, "HIGH")).isTrue();
        assertThat(SiemSeverityFilter.admits(SecurityEventType.ACCOUNT_CHANGED, "HIGH")).isFalse();
        assertThat(SiemSeverityFilter.admits(SecurityEventType.API_KEY_REVOKED, "HIGH")).isFalse();
    }

    @Test
    @DisplayName("MEDIUM forwards 4 and above, LOW everything")
    void mediumAndLow() {
        assertThat(SiemSeverityFilter.admits(SecurityEventType.API_KEY_REVOKED, "MEDIUM")).isTrue();
        assertThat(SiemSeverityFilter.admits(SecurityEventType.API_KEY_REVOKED, "medium")).isTrue();
        assertThat(SiemSeverityFilter.admits(SecurityEventType.API_KEY_REVOKED, "LOW")).isTrue();
    }

    @ParameterizedTest(name = "\"{0}\" forwards everything")
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "SEVERE", "UNKNOWN"})
    void noOrUnreadableThresholdSendsEverything(String stored) {
        // Silence nobody sees is the failure not worth having in a security feed.
        for (SecurityEventType type : SecurityEventType.values()) {
            assertThat(SiemSeverityFilter.admits(type, stored)).as(type.name()).isTrue();
        }
    }

    @Test
    @DisplayName("the connection test goes through whatever the threshold")
    void pingAlwaysPasses() {
        assertThat(SiemSeverityFilter.admits(SecurityEventType.PING_TEST, "CRITICAL")).isTrue();
    }
}

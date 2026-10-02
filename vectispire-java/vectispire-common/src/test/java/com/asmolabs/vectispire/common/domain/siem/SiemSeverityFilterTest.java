package com.asmolabs.vectispire.common.domain.siem;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.Severity;
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
        assertThat(admits(SecurityEventType.AUDIT_CHAIN_BROKEN, "CRITICAL")).isTrue();
        assertThat(admits(SecurityEventType.CRITICAL_KEV_DETECTED, "CRITICAL")).isTrue();
        assertThat(admits(SecurityEventType.AGENT_RESULT_REFUSED, "CRITICAL")).isFalse();
        assertThat(admits(SecurityEventType.SIGN_IN_THROTTLED, "CRITICAL")).isFalse();
    }

    @Test
    @DisplayName("HIGH forwards 7 and above, and not a medium")
    void high() {
        assertThat(admits(SecurityEventType.SIGN_IN_THROTTLED, "HIGH")).isTrue();
        assertThat(admits(SecurityEventType.SECURITY_GATE_FAILED, "HIGH")).isTrue();
        assertThat(admits(SecurityEventType.ACCOUNT_CHANGED, "HIGH")).isFalse();
        assertThat(admits(SecurityEventType.API_KEY_REVOKED, "HIGH")).isFalse();
    }

    @Test
    @DisplayName("MEDIUM forwards 4 and above, LOW everything")
    void mediumAndLow() {
        assertThat(admits(SecurityEventType.API_KEY_REVOKED, "MEDIUM")).isTrue();
        assertThat(admits(SecurityEventType.API_KEY_REVOKED, "medium")).isTrue();
        assertThat(admits(SecurityEventType.API_KEY_REVOKED, "LOW")).isTrue();
    }

    @ParameterizedTest(name = "\"{0}\" forwards everything")
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "SEVERE", "UNKNOWN"})
    void noOrUnreadableThresholdSendsEverything(String stored) {
        // Silence nobody sees is the failure not worth having in a security feed.
        for (SecurityEventType type : SecurityEventType.values()) {
            assertThat(admits(type, stored)).as(type.name()).isTrue();
        }
    }

    @Test
    @DisplayName("the connection test goes through whatever the threshold")
    void pingAlwaysPasses() {
        assertThat(admits(SecurityEventType.PING_TEST, "CRITICAL")).isTrue();
    }

    @Test
    @DisplayName("at the factory minimum, HIGH, a critical or high issue's deadline breach is forwarded, a medium or low one's is not")
    void slaBreachesAtTheDefault() {
        assertThat(SiemSeverityFilter.admits(breachOf(Severity.CRITICAL), "HIGH")).isTrue();
        assertThat(SiemSeverityFilter.admits(breachOf(Severity.HIGH), "HIGH")).isTrue();
        assertThat(SiemSeverityFilter.admits(breachOf(Severity.MEDIUM), "HIGH")).isFalse();
        assertThat(SiemSeverityFilter.admits(breachOf(Severity.LOW), "HIGH")).isFalse();
    }

    @Test
    @DisplayName("MEDIUM lets a medium issue's breach through and still not a low one's")
    void slaBreachesAtMedium() {
        assertThat(SiemSeverityFilter.admits(breachOf(Severity.MEDIUM), "MEDIUM")).isTrue();
        assertThat(SiemSeverityFilter.admits(breachOf(Severity.LOW), "MEDIUM")).isFalse();
        assertThat(SiemSeverityFilter.admits(breachOf(Severity.LOW), "LOW")).isTrue();
    }

    private static CefEvent breachOf(Severity issueSeverity) {
        return CefEvent.builder(SecurityEventType.SLA_BREACHED).issueSeverity(issueSeverity).build();
    }

    private static boolean admits(SecurityEventType type, String stored) {
        return SiemSeverityFilter.admits(CefEvent.builder(type).build(), stored);
    }
}

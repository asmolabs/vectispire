package com.asmolabs.zanshin.common.domain.notifications;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.notifications.NotificationPayload.NotifiableIssue;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("notifications")
class NotificationsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-08-13T10:00:00Z");

    private static NotifiableIssue issue(long id, FindingType type, Severity severity, boolean kev) {
        return new NotifiableIssue(id, "CVE-" + id, type, severity, kev, null, "pkg", null, "1.2.3", null);
    }

    @Nested
    @DisplayName("choosing what deserves a message")
    class Selection {

        private static final NotificationSelection.Options DEFAULTS =
                new NotificationSelection.Options(Severity.HIGH, true);

        @Test
        @DisplayName("quality findings never qualify, whatever their severity")
        void qualityNeverNotifies() {
            // Semgrep maps its ERROR level to `high`, which clears the default threshold: the
            // first scan with SAST on would fire a webhook announcing several hundred issues.
            List<NotifiableIssue> issues = List.of(issue(1, FindingType.QUALITY, Severity.CRITICAL, true));

            assertThat(NotificationSelection.notable(issues, DEFAULTS)).isEmpty();
        }

        @Test
        @DisplayName("an exploited vulnerability passes whatever its severity")
        void kevBypassesTheThreshold() {
            // A threshold alone discards a "medium" being exploited today, which is the one
            // thing the KEV signal exists to surface.
            List<NotifiableIssue> issues = List.of(issue(1, FindingType.VULNERABILITY, Severity.LOW, true));

            assertThat(NotificationSelection.notable(issues, DEFAULTS)).hasSize(1);
            assertThat(NotificationSelection.notable(issues, new NotificationSelection.Options(Severity.HIGH, false)))
                    .isEmpty();
        }

        @Test
        @DisplayName("applies the severity threshold otherwise")
        void appliesTheThreshold() {
            assertThat(NotificationSelection.notable(
                            List.of(
                                    issue(1, FindingType.VULNERABILITY, Severity.CRITICAL, false),
                                    issue(2, FindingType.VULNERABILITY, Severity.MEDIUM, false)),
                            DEFAULTS))
                    .extracting(NotifiableIssue::id)
                    .containsExactly(1L);
        }

        @Test
        @DisplayName("an issue with no severity ranks lowest rather than alerting")
        void missingSeverityRanksLowest() {
            List<NotifiableIssue> issues = List.of(issue(1, FindingType.VULNERABILITY, null, false));

            assertThat(NotificationSelection.notable(issues, DEFAULTS)).isEmpty();
        }
    }

    @Nested
    @DisplayName("the payload")
    class Payload {

        @Test
        @DisplayName("leads with a readable line, for receivers that read only that")
        void textComesFirst() {
            NotificationPayload payload = NotificationPayload.of(new NotificationPayload.Delta(
                    "api-service", 42,
                    List.of(issue(1, FindingType.VULNERABILITY, Severity.HIGH, true)),
                    List.of(issue(2, FindingType.VULNERABILITY, Severity.HIGH, false)),
                    3, Severity.HIGH));

            assertThat(payload.text())
                    .isEqualTo("Zanshin — api-service: 1 new issue(s), 1 reappeared, 1 actively exploited (3 resolved)");
        }

        @Test
        @DisplayName("names at most ten issues and counts the rest")
        void truncatesTheDetail() {
            // A body with four hundred entries is a denial of service against its reader, and
            // the API is there for the full list.
            List<NotifiableIssue> many = IntStream.range(0, 25)
                    .mapToObj(i -> issue(i, FindingType.VULNERABILITY, Severity.HIGH, false))
                    .toList();

            NotificationPayload payload = NotificationPayload.of(
                    new NotificationPayload.Delta("api-service", 1, many, List.of(), 0, Severity.HIGH));

            assertThat(payload.issues()).hasSize(NotificationPayload.MAX_DETAILED_ISSUES);
            assertThat(payload.truncated()).isEqualTo(15);
        }

        @Test
        @DisplayName("serializes with snake_case keys, as the documented body says")
        void serializesTheDocumentedShape() throws Exception {
            String json = MAPPER.writeValueAsString(NotificationPayload.of(new NotificationPayload.Delta(
                    "api-service", 42, List.of(issue(1, FindingType.VULNERABILITY, Severity.HIGH, true)),
                    List.of(), 0, Severity.HIGH)));
            JsonNode node = MAPPER.readTree(json);

            assertThat(node.fieldNames()).toIterable().startsWith("text");
            assertThat(node.get("scan_id").asInt()).isEqualTo(42);
            assertThat(node.get("kev_count").asInt()).isEqualTo(1);
            assertThat(node.get("issues").get(0).get("is_kev").asBoolean()).isTrue();
            assertThat(node.get("issues").get(0).get("fix_versions").asText()).isEqualTo("1.2.3");
        }
    }

    @Nested
    @DisplayName("outbox retries")
    class Retry {

        @ParameterizedTest(name = "attempt {0} waits {1} seconds")
        @CsvSource({"0, 60", "1, 60", "2, 120", "3, 240", "7, 3600", "8, 3600"})
        void backsOffExponentiallyThenCaps(int attempts, long seconds) {
            // Retrying a misconfigured webhook every sixty seconds turns a typo into permanent
            // load; capping stops the widening from becoming an outage nobody notices.
            assertThat(OutboxRetry.backoff(attempts)).isEqualTo(Duration.ofSeconds(seconds));
        }

        @Test
        @DisplayName("a corrupted attempt counter cannot produce a negative delay")
        void hugeCountersStayCapped() {
            // An unbounded shift wraps and retries at once, forever — the failure mode of a
            // backoff written without a ceiling on the exponent itself.
            assertThat(OutboxRetry.backoff(Integer.MAX_VALUE)).isEqualTo(OutboxRetry.MAX_BACKOFF);
        }

        @Test
        @DisplayName("abandons after the last attempt, and says so rather than rescheduling")
        void abandonsEventually() {
            assertThat(OutboxRetry.nextAttemptAt(OutboxRetry.MAX_ATTEMPTS - 1, NOW)).isPresent();
            assertThat(OutboxRetry.nextAttemptAt(OutboxRetry.MAX_ATTEMPTS, NOW)).isEmpty();
            assertThat(OutboxRetry.isAbandoned(OutboxRetry.MAX_ATTEMPTS)).isTrue();
        }

        @Test
        @DisplayName("truncates the recorded error")
        void truncatesTheError() {
            // A proxy's HTML error page is not worth a kilobyte per attempt in a table written
            // on every scan.
            String recorded = OutboxRetry.recordableError(new IllegalStateException("x".repeat(2000)));

            assertThat(recorded).hasSize(500).startsWith("IllegalStateException: ");
        }

        @Test
        @DisplayName("records something even for an error with no message")
        void handlesEmptyErrors() {
            assertThat(OutboxRetry.recordableError(null)).isEqualTo("unknown error");
            assertThat(OutboxRetry.recordableError(new RuntimeException())).contains("RuntimeException");
        }
    }
}

package com.asmolabs.vectispire.common.domain.notifications;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * What Teams and a mailbox actually receive.
 *
 * <p>Both renderings are pure functions of the payload, which is the reason they live in the
 * domain: the shape a channel expects is the part that goes wrong, and it can be asserted here
 * without a webhook, a relay or a clock.
 */
@DisplayName("rendering an alert for its destination")
class TeamsAndMailTest {

    private static NotificationPayload payload(int newCount, long kev, List<NotificationPayload.Detail> issues) {
        return new NotificationPayload(
                "3 new findings on Arm Libs Spring",
                "Arm Libs Spring",
                34,
                newCount,
                1,
                2,
                kev,
                "high",
                issues,
                0,
                "msg-1");
    }

    private static NotificationPayload.Detail issue(String identifier, String severity, boolean kev) {
        return new NotificationPayload.Detail(
                7, identifier, "vulnerability", severity, kev, 0.42,
                "openssl 3.0.1", null, "3.0.14", "https://example.com/cve");
    }

    @Nested
    @DisplayName("the Teams card")
    class Teams {

        @SuppressWarnings("unchecked")
        private Map<String, Object> cardOf(NotificationPayload payload, String publicUrl) {
            Map<String, Object> envelope = TeamsCard.of(payload, publicUrl);
            List<Map<String, Object>> attachments = (List<Map<String, Object>>) envelope.get("attachments");
            return (Map<String, Object>) attachments.getFirst().get("content");
        }

        @Test
        @DisplayName("is wrapped in the envelope a workflow expects, not posted bare")
        void theEnvelopeIsTheContract() {
            // A workflow handed a bare card posts nothing and reports success — the failure this
            // codebase keeps naming. The envelope is what makes the difference.
            Map<String, Object> envelope = TeamsCard.of(payload(3, 0, List.of()), null);

            assertThat(envelope.get("type")).isEqualTo("message");
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> attachments = (List<Map<String, Object>>) envelope.get("attachments");
            assertThat(attachments).hasSize(1);
            assertThat(attachments.getFirst().get("contentType"))
                    .isEqualTo("application/vnd.microsoft.card.adaptive");
            assertThat(attachments.getFirst()).containsKey("contentUrl");
        }

        @Test
        @DisplayName("names the target, the scan and the counts")
        void theCardCarriesTheDelta() {
            String rendered = cardOf(payload(3, 0, List.of(issue("CVE-2026-1234", "critical", false))), null)
                    .toString();

            assertThat(rendered).contains("Arm Libs Spring");
            assertThat(rendered).contains("scan #34");
            assertThat(rendered).contains("CVE-2026-1234");
            assertThat(rendered).contains("3.0.14");
        }

        @Test
        @DisplayName("expresses severity in the four colours Teams knows")
        void severityUsesTheClientsPalette() {
            // Adaptive Cards have no palette, only these names. A hexadecimal would be ignored,
            // and the card would render every finding in the same colour.
            String critical = cardOf(payload(1, 0, List.of(issue("CVE-1", "critical", false))), null).toString();
            String low = cardOf(payload(1, 0, List.of(issue("CVE-2", "low", false))), null).toString();

            assertThat(critical).contains("attention");
            assertThat(low).doesNotContain("attention");
        }

        @Test
        @DisplayName("counts what is exploited only when something is")
        void theExploitedRowAppearsOnlyWhenItMatters() {
            // A row reading "Actively exploited: 0" trains the eye to skip the line that matters
            // on the day it is not zero.
            assertThat(cardOf(payload(1, 0, List.of()), null).toString()).doesNotContain("Actively exploited");
            assertThat(cardOf(payload(1, 2, List.of()), null).toString()).contains("Actively exploited");
        }

        @Test
        @DisplayName("offers a way back only when the deployment knows its own address")
        void theButtonNeedsAnAddress() {
            // An unreachable link is worse than none.
            assertThat(cardOf(payload(1, 0, List.of()), null)).doesNotContainKey("actions");
            assertThat(cardOf(payload(1, 0, List.of()), "https://vectispire.example.com/").toString())
                    .contains("https://vectispire.example.com/issues");
        }
    }

    @Nested
    @DisplayName("the e-mail")
    class Mail {

        @Test
        @DisplayName("puts the verdict in the subject, where a mailbox shows it")
        void theSubjectDecidesWhetherItIsOpened() {
            MailMessage.Content content = MailMessage.of(payload(3, 0, List.of()), null);

            assertThat(content.subject()).contains("Arm Libs Spring");
            assertThat(content.subject()).contains("3 new");
        }

        @Test
        @DisplayName("leads with what is exploited, the only figure that changes today's plan")
        void exploitationLeads() {
            assertThat(MailMessage.of(payload(3, 1, List.of()), null).subject()).startsWith("[exploited]");
            assertThat(MailMessage.of(payload(3, 0, List.of()), null).subject()).doesNotContain("[exploited]");
        }

        @Test
        @DisplayName("carries where the finding is and what fixes it")
        void thebodyCarriesWhatIsActedOn() {
            String body = MailMessage.of(payload(1, 0, List.of(issue("CVE-2026-1234", "high", false))), null).body();

            assertThat(body).contains("CVE-2026-1234");
            assertThat(body).contains("openssl 3.0.1");
            assertThat(body).contains("fixed in 3.0.14");
        }

        @Test
        @DisplayName("names the message, because delivery is at-least-once")
        void theReaderCanRecogniseARepeat() {
            assertThat(MailMessage.of(payload(1, 0, List.of()), null).body()).contains("msg-1");
        }
    }
}

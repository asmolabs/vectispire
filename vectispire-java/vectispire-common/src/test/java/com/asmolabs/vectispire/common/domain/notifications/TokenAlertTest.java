package com.asmolabs.vectispire.common.domain.notifications;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert.Credential;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert.Notice;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * An integration token's change of state, as each channel says it.
 *
 * <p>One case per channel and per transition: the five ways a token's state changes — about to expire, expired,
 * refused, working again, no longer about to expire — rendered for the generic webhook, Slack, Teams, Discord and
 * mail, each required to say which change it is, to name the connection, and to carry no secret.
 */
@DisplayName("a token's change of state, said")
class TokenAlertTest {

    private static final Instant EXPIRY = Instant.parse("2026-10-27T00:00:00Z");
    private static final Instant NOW = Instant.parse("2026-10-13T08:00:00Z");

    /** Written by an administrator: markup in every chat that renders one, and a header break in a mail. */
    private static final String HOSTILE_NAME = "Platform <!channel> [x](https://evil.example) @everyone\r\nBcc: x";

    enum Transition {
        EXPIRES_SOON(Notice.NONE, Notice.EXPIRES_SOON, "expires on 2026-10-27T00:00:00Z",
                AuditOperation.INTEGRATION_TOKEN_EXPIRING, "VECTI-SEC-038", 4),
        EXPIRED(Notice.EXPIRES_SOON, Notice.EXPIRED, "expired on 2026-10-27T00:00:00Z",
                AuditOperation.INTEGRATION_TOKEN_STOPPED, "VECTI-SEC-039", 7),
        REFUSED(Notice.NONE, Notice.REFUSED, "is refused by the server (HTTP 401) since 2026-10-12T08:00:00Z",
                AuditOperation.INTEGRATION_TOKEN_STOPPED, "VECTI-SEC-039", 7),
        WORKS_AGAIN(Notice.REFUSED, Notice.NONE, "works again",
                AuditOperation.INTEGRATION_TOKEN_RESTORED, "VECTI-SEC-040", 2),
        NO_LONGER_EXPIRING(Notice.EXPIRES_SOON, Notice.NONE, "is no longer about to expire",
                AuditOperation.INTEGRATION_TOKEN_RESTORED, "VECTI-SEC-040", 2);

        final Notice previous;
        final Notice notice;
        final String says;
        final AuditOperation operation;
        final String signature;
        final int severity;

        Transition(Notice previous, Notice notice, String says, AuditOperation operation, String signature, int severity) {
            this.previous = previous;
            this.notice = notice;
            this.says = says;
            this.operation = operation;
            this.signature = signature;
            this.severity = severity;
        }

        TokenAlert alert(Credential credential, String name) {
            return new TokenAlert(credential, credential == Credential.TRACKER_TOKEN ? "ticket_token" : "b7c0-connection",
                    name, "GitLab at https://gitlab.example.com", notice, previous,
                    notice == Notice.NONE ? null : EXPIRY,
                    notice == Notice.REFUSED ? 401 : null,
                    notice == Notice.REFUSED ? Instant.parse("2026-10-12T08:00:00Z") : null,
                    NOW);
        }
    }

    enum Channel { WEBHOOK, SLACK, TEAMS, DISCORD, MAIL }

    static Stream<Arguments> everyChannelAndTransition() {
        List<Arguments> cases = new ArrayList<>();
        for (Channel channel : Channel.values()) {
            for (Transition transition : Transition.values()) {
                cases.add(Arguments.of(channel, transition));
            }
        }
        return cases.stream();
    }

    @ParameterizedTest(name = "{0}: {1}")
    @MethodSource("everyChannelAndTransition")
    @DisplayName("each channel says which change it is, names the forge connection, and carries no token")
    void eachChannelSaysEachChange(Channel channel, Transition transition) throws Exception {
        TokenAlert alert = transition.alert(Credential.FORGE_CONNECTION, "Platform GitLab");

        String rendered = render(channel, alert);

        // Discord's markdown escapes the parentheses of "(HTTP 401)": the same words, rendered as text.
        String escaped = channel == Channel.DISCORD ? ChatText.discord(transition.says) : transition.says;
        // And a JSON body writes that escape's backslash twice.
        String quoted = new ObjectMapper().writeValueAsString(escaped);
        String says = channel == Channel.MAIL ? escaped : quoted.substring(1, quoted.length() - 1);
        assertThat(rendered).contains(says).contains("Platform GitLab")
                .contains("https://gitlab.example.com");
        assertThat(rendered).doesNotContainIgnoringCase("token=").doesNotContainIgnoringCase("private-token")
                .doesNotContainIgnoringCase("authorization").doesNotContain("glpat");
        if (channel != Channel.WEBHOOK) {
            assertThat(rendered).as("a link back to where the token is replaced").contains("https://vectispire.example.com/forge-connections");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("transitions")
    @DisplayName("each change is its own audit operation and SIEM event, stopped above expiring, working again informational")
    void eachChangeIsItsEvent(Transition transition) {
        TokenAlert alert = transition.alert(Credential.TRACKER_TOKEN, "GitLab");

        assertThat(alert.operation()).isEqualTo(transition.operation);
        assertThat(alert.signal().signatureId()).isEqualTo(transition.signature);
        assertThat(alert.signal().cefSeverity()).isEqualTo(transition.severity);
        // The audit log's hook finds the event by the operation alone: the writer has nothing to name.
        assertThat(SecurityEventType.signalledBy(alert.operation())).contains(alert.signal());
        assertThat(alert.sentence()).startsWith("The tracker token (GitLab at https://gitlab.example.com)")
                .contains(transition.says);
    }

    static Stream<Transition> transitions() {
        return Stream.of(Transition.values());
    }

    @Test
    @DisplayName("stopped working outranks expiring soon, which outranks working again")
    void severitiesAreOrdered() {
        assertThat(SecurityEventType.INTEGRATION_TOKEN_STOPPED.cefSeverity())
                .isGreaterThan(SecurityEventType.INTEGRATION_TOKEN_EXPIRING.cefSeverity());
        assertThat(SecurityEventType.INTEGRATION_TOKEN_EXPIRING.cefSeverity())
                .isGreaterThan(SecurityEventType.INTEGRATION_TOKEN_RESTORED.cefSeverity());
        // Informational: the low band, under any minimum but LOW.
        assertThat(SecurityEventType.INTEGRATION_TOKEN_RESTORED.cefSeverity()).isLessThanOrEqualTo(3);
        // At the factory minimum (HIGH, 7 and above), so it reaches a SOC out of the box.
        assertThat(SecurityEventType.INTEGRATION_TOKEN_STOPPED.cefSeverity()).isGreaterThanOrEqualTo(7);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("channels")
    @DisplayName("a connection's name is inert: no mention, no link, no second mail header")
    void aHostileNameIsInert(Channel channel) throws Exception {
        TokenAlert alert = Transition.EXPIRED.alert(Credential.FORGE_CONNECTION, HOSTILE_NAME);

        String rendered = render(channel, alert);

        assertThat(rendered).doesNotContain("\r\nBcc").doesNotContain("\nBcc");
        switch (channel) {
            case SLACK -> assertThat(rendered).doesNotContain("<!channel>").contains("&lt;!channel&gt;");
            case DISCORD -> assertThat(rendered).doesNotContain("[x](https://evil.example)").doesNotContain("@everyone");
            case TEAMS -> assertThat(rendered).doesNotContain("[x](https://evil.example)");
            case MAIL -> assertThat(TokenAlertMessages.mail(alert, null, "m-1").subject()).doesNotContain("\n", "\r");
            case WEBHOOK -> assertThat(rendered).doesNotContain("\\r\\nBcc");
        }
    }

    static Stream<Channel> channels() {
        return Stream.of(Channel.values());
    }

    @Test
    @DisplayName("the generic webhook is told apart from a scan's delta, and carries its message id")
    void theWebhookBodyNamesItsEvent() {
        Map<String, Object> body = TokenAlertMessages.webhook(Transition.REFUSED.alert(Credential.TRACKER_TOKEN, "GitLab"),
                "m-42");

        assertThat(body).containsEntry("event", "token_state_changed")
                .containsEntry("credential", "tracker_token")
                .containsEntry("state", "refused")
                .containsEntry("previous_state", "none")
                .containsEntry("signature_id", "VECTI-SEC-039")
                .containsEntry("refused_status", 401)
                .containsEntry("message_id", "m-42")
                .doesNotContainKey("scan_id");
    }

    @Test
    @DisplayName("an absent or unknown stored value reads as nothing said")
    void storedValues() {
        assertThat(Notice.read(null)).isEqualTo(Notice.NONE);
        assertThat(Notice.read("")).isEqualTo(Notice.NONE);
        assertThat(Notice.read("something-newer")).isEqualTo(Notice.NONE);
        for (Notice notice : Notice.values()) {
            assertThat(Notice.read(notice.wireName())).isEqualTo(notice);
        }
    }

    private static String render(Channel channel, TokenAlert alert) throws Exception {
        String publicUrl = "https://vectispire.example.com/";
        ObjectMapper json = new ObjectMapper();
        return switch (channel) {
            case WEBHOOK -> json.writeValueAsString(TokenAlertMessages.webhook(alert, "m-1"));
            case SLACK -> json.writeValueAsString(TokenAlertMessages.slack(alert, publicUrl));
            case TEAMS -> json.writeValueAsString(TokenAlertMessages.teams(alert, publicUrl));
            case DISCORD -> json.writeValueAsString(TokenAlertMessages.discord(alert, publicUrl));
            case MAIL -> {
                MailMessage.Content mail = TokenAlertMessages.mail(alert, publicUrl, "m-1");
                yield mail.subject() + "\n" + mail.body();
            }
        };
    }
}

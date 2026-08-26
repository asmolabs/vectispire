package com.asmolabs.vectispire.common.domain.tickets;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.tickets.WebhookAuthenticity.Presented;
import com.asmolabs.vectispire.common.domain.tickets.WebhookAuthenticity.Verdict;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The only anonymous mutating door in the system, and what closes it.
 *
 * <p>The webhook route cannot require a session — the caller is Jira — and what it does is move a
 * triage decision. These cases are the difference between "anybody who guesses a ticket reference"
 * and "the tracker we configured".
 */
@DisplayName("inbound webhook authenticity")
class WebhookAuthenticityTest {

    private static final String SECRET = "s3cr3t-shared-with-the-tracker";
    private static final String BODY = "{\"issue\":{\"key\":\"SEC-42\"},\"action\":\"resolved\"}";

    @Test
    @DisplayName("no secret configured leaves the route open, as every existing deployment has it")
    void unsetSecretIsNotEnforced() {
        // Deliberate: refusing unsigned calls on upgrade would stop triage synchronising silently
        // everywhere, which is a worse failure than the one this closes because nobody sees it.
        assertThat(WebhookAuthenticity.verify(
                        TicketProvider.GITLAB, null, new Presented(null, null, null), BODY))
                .isEqualTo(Verdict.NOT_ENFORCED);
        assertThat(WebhookAuthenticity.verify(
                        TicketProvider.GITLAB, "   ", new Presented(null, null, null), BODY))
                .isEqualTo(Verdict.NOT_ENFORCED);
    }

    @Test
    @DisplayName("GitLab presents the secret verbatim")
    void gitlabTokenIsCompared() {
        assertThat(WebhookAuthenticity.verify(
                        TicketProvider.GITLAB, SECRET, new Presented(SECRET, null, null), BODY))
                .isEqualTo(Verdict.ACCEPTED);
        assertThat(WebhookAuthenticity.verify(
                        TicketProvider.GITLAB, SECRET, new Presented("wrong", null, null), BODY))
                .isEqualTo(Verdict.REJECTED);
        // A caller presenting nothing at all is the common case, and it must not pass.
        assertThat(WebhookAuthenticity.verify(
                        TicketProvider.GITLAB, SECRET, new Presented(null, null, null), BODY))
                .isEqualTo(Verdict.REJECTED);
    }

    @Test
    @DisplayName("GitHub signs the exact body, prefix included")
    void githubSignatureCoversTheBody() {
        String signature = "sha256=" + WebhookAuthenticity.hmacSha256Hex(SECRET, BODY);

        assertThat(WebhookAuthenticity.verify(
                        TicketProvider.GITHUB, SECRET, new Presented(null, signature, null), BODY))
                .isEqualTo(Verdict.ACCEPTED);

        // **The body is what is signed, so a changed body must fail an unchanged signature.**
        // Without this the check would accept a replayed header over any payload at all.
        assertThat(WebhookAuthenticity.verify(
                        TicketProvider.GITHUB, SECRET, new Presented(null, signature, null),
                        BODY.replace("resolved", "reopened")))
                .isEqualTo(Verdict.REJECTED);

        // The `sha256=` prefix is part of what GitHub sends; accepting the bare hex would accept
        // something GitHub never produces.
        assertThat(WebhookAuthenticity.verify(
                        TicketProvider.GITHUB, SECRET,
                        new Presented(null, WebhookAuthenticity.hmacSha256Hex(SECRET, BODY), null), BODY))
                .isEqualTo(Verdict.REJECTED);
    }

    @Test
    @DisplayName("Jira and ServiceNow sign nothing, so a shared token is the whole check")
    void trackersWithoutAConventionUseASharedToken() {
        for (TicketProvider provider : new TicketProvider[] {TicketProvider.JIRA, TicketProvider.SERVICENOW}) {
            assertThat(WebhookAuthenticity.verify(provider, SECRET, new Presented(null, null, SECRET), BODY))
                    .as("%s", provider)
                    .isEqualTo(Verdict.ACCEPTED);
            assertThat(WebhookAuthenticity.verify(provider, SECRET, new Presented(null, null, "wrong"), BODY))
                    .as("%s", provider)
                    .isEqualTo(Verdict.REJECTED);
        }
    }

    @Test
    @DisplayName("a header meant for another tracker does not authenticate this one")
    void headersAreNotInterchangeable() {
        // A caller who learned the secret from a GitLab setup must not be able to present it as a
        // GitHub signature, or the three shapes would collapse into one weakest one.
        assertThat(WebhookAuthenticity.verify(
                        TicketProvider.GITHUB, SECRET, new Presented(SECRET, null, SECRET), BODY))
                .isEqualTo(Verdict.REJECTED);
        assertThat(WebhookAuthenticity.verify(
                        TicketProvider.GITLAB, SECRET,
                        new Presented(null, "sha256=" + WebhookAuthenticity.hmacSha256Hex(SECRET, BODY), SECRET),
                        BODY))
                .isEqualTo(Verdict.REJECTED);
    }

    @Test
    @DisplayName("the hex is lower-case and stable, which is the wire format")
    void theEncodingIsPinned() {
        // Pinned against a literal rather than recomputed: a round trip through this method on
        // both sides would agree with itself while disagreeing with GitHub.
        assertThat(WebhookAuthenticity.hmacSha256Hex("key", "message"))
                .isEqualTo("6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a");
    }
}

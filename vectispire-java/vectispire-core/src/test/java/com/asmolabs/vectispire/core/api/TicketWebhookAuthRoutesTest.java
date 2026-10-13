package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.WebhookAuthenticity;
import com.asmolabs.vectispire.core.settings.SettingsService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The webhook route, over HTTP, with and without a configured secret.
 *
 * <p>{@code WebhookAuthenticityTest} owns the comparison itself. What this adds is the wiring: the
 * headers really are read, the setting really is consulted, and an unsigned call really is refused
 * — none of which the domain test can see.
 */
@DisplayName("the ticketing webhook's authentication")
class TicketWebhookAuthRoutesTest extends ApiTestBase {

    private static final String BODY =
            "{\"object_attributes\":{\"iid\":42,\"state\":\"closed\"},\"event_type\":\"issue\"}";

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("with no secret configured the route accepts nothing, and says why")
    void closedWhenUnset() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "");

        // It answered 200 here, on the grounds that closing the door would stop existing
        // deployments synchronising unnoticed. Behind that 200, a stranger queued a "not affected"
        // for any ticket reference they guessed. The refusal names its cause, because it lands in
        // the tracker's delivery log and that is where a broken integration is looked for.
        mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.detail").value(org.hamcrest.Matchers.containsString("not configured")))
                .andExpect(jsonPath("$.actionTaken").doesNotExist());
    }

    @Test
    @DisplayName("a secret no key can decrypt refuses the tracker, and the screen stops claiming one")
    void anUnreadableSecretDoesNotReopenTheRoute() throws Exception {
        // A lost ENCRYPTION_KEY or a dropped previous key made the stored secret unreadable, and the
        // tolerant read turned that into "no secret" — the route reopened to unsigned calls while
        // the settings screen still said a secret was configured.
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY))
                .andExpect(status().isUnauthorized());

        mvc.perform(authenticated(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get(
                                "/api/v1/settings/ticket-webhook-secret"),
                        asAdmin()))
                .andExpect(status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.configured")
                        .value(false));
    }

    @Test
    @DisplayName("with a secret configured an unsigned call is refused")
    void refusedWhenUnsigned() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "shared-with-gitlab");

        // The whole point: before this, an anonymous caller who guessed a ticket reference could
        // close a finding.
        mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY))
                .andExpect(status().isUnauthorized());

        MvcResult guessed = mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                        .header("X-Gitlab-Token", "guessed")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.matched").doesNotExist())
                .andReturn();
        // No more than that: a caller learning which header was wrong learns which tracker we expect.
        assertThat(detailOf(guessed)).isEqualTo("Webhook authentication failed");
    }

    @Test
    @DisplayName("a provider it does not know, and a body that is not JSON, are 400 problems")
    void malformedDeliveriesAreProblems() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "shared-with-gitlab");

        MvcResult unknown = mvc.perform(post("/api/v1/tickets/webhook/bitbucket")
                        .header("X-Vectispire-Token", "shared-with-gitlab")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andReturn();
        assertThat(detailOf(unknown)).isEqualTo("Unsupported provider: bitbucket");

        MvcResult notJson = mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                        .header("X-Gitlab-Token", "shared-with-gitlab")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{not json"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andReturn();
        assertThat(detailOf(notJson)).isEqualTo("Malformed JSON body");
    }

    @Test
    @DisplayName("the tracker's own token is accepted — GitLab verbatim, GitHub signed")
    void acceptedWhenPresented() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "shared-with-gitlab");

        mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                        .header("X-Gitlab-Token", "shared-with-gitlab")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY))
                .andExpect(status().isOk());

        // The signature covers the exact bytes posted, which is why the controller keeps the raw
        // string rather than re-serialising what it parsed.
        mvc.perform(post("/api/v1/tickets/webhook/github")
                        .header("X-Hub-Signature-256",
                                "sha256=" + WebhookAuthenticity.hmacSha256Hex("shared-with-gitlab", BODY))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY))
                .andExpect(status().isOk());
    }
}

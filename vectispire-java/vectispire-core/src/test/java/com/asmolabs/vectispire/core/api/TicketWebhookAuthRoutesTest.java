package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.WebhookAuthenticity;
import com.asmolabs.vectispire.core.services.SettingsService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

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
    @DisplayName("with no secret configured the route stays open, as every deployment has it today")
    void openWhenUnset() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "");

        // 200 rather than 401: this is the behaviour every existing deployment relies on, and
        // changing it on upgrade would stop their triage synchronising without anybody noticing.
        mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY))
                .andExpect(status().isOk());
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

        mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                        .header("X-Gitlab-Token", "guessed")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(BODY))
                .andExpect(status().isUnauthorized());
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

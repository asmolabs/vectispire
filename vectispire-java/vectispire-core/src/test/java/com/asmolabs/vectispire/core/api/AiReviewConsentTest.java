package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.services.SettingsService;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Turning the public model endpoint on, and — the part that was missing — off again.
 *
 * <p><b>Granting consent was guarded; withdrawing it was refused.</b> The pre-save check asks
 * whether the configuration this request produces may send source code off-site, and refuses a
 * public destination without an acknowledgement. Switching the acknowledgement off while the
 * provider was still {@code openai} therefore produced a 422 naming a URL the operator had not
 * touched, and the only way out — send both changes in one request — was written down nowhere. A
 * guard that stops a configuration becoming safer is pointing the wrong way, and it bought
 * nothing: {@code AiReview.validatedUrl()} runs the same guard on every review.
 */
@DisplayName("consent to a public model endpoint")
class AiReviewConsentTest extends ApiTestBase {

    @Autowired
    private SettingsService settings;

    private int save(Map<String, String> body) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andReturn().getResponse().getStatus();
    }

    private static Map<String, String> body(String... pairs) {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put(pairs[i], pairs[i + 1]);
        }
        return map;
    }

    @Test
    @DisplayName("a public provider is refused until somebody accepts the risk")
    void refusedWithoutAcceptance() throws Exception {
        assertThat(save(body("ai_review_provider", "openai")))
                .as("selecting OpenAI with no acknowledgement stored the configuration anyway")
                .isEqualTo(422);
        assertThat(settings.get(Setting.AI_REVIEW_PROVIDER)).isNotEqualTo("openai");
    }

    @Test
    @DisplayName("accepting it records who did, from the session rather than the request")
    void acceptanceIsStampedByTheServer() throws Exception {
        assertThat(save(body("ai_review_provider", "openai", "ai_review_allow_remote_url", "true")))
                .isEqualTo(200);

        assertThat(settings.get(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_BY)).startsWith("admin-");
        assertThat(settings.get(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_AT)).isNotBlank();
    }

    @Test
    @DisplayName("withdrawing it is accepted, and erases the record")
    void withdrawalIsAccepted() throws Exception {
        assertThat(save(body("ai_review_provider", "openai", "ai_review_allow_remote_url", "true")))
                .isEqualTo(200);

        // On its own, with the provider left where it is. This is the request that answered 422:
        // the operator who wants to stop sending code off-site was told the URL was public, which
        // they knew, and not what to do about it.
        assertThat(save(body("ai_review_allow_remote_url", "false")))
                .as("withdrawing the acknowledgement was refused, so the safest reachable "
                        + "configuration was one the settings screen could not save")
                .isEqualTo(200);

        assertThat(settings.get(Setting.AI_REVIEW_ALLOW_REMOTE)).isEqualTo("false");
        assertThat(settings.get(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_BY)).isEmpty();
        assertThat(settings.get(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_AT)).isEmpty();
    }

    @Test
    @DisplayName("and the review then sends nowhere, which is what made the refusal pointless")
    void theRuntimeGuardStillRefuses() throws Exception {
        save(body("ai_review_provider", "openai", "ai_review_allow_remote_url", "true"));
        save(body("ai_review_allow_remote_url", "false"));

        // The stored configuration is now "openai, not acknowledged" — the state the pre-save
        // check used to refuse to let anyone reach. It is inert: every review revalidates the
        // destination, so nothing leaves. Asserted here because it is the whole argument for
        // allowing the withdrawal in the first place.
        assertThat(save(body("ai_review_provider", "openai")))
                .as("the destination is no longer revalidated on save")
                .isEqualTo(422);
    }

    @Test
    @DisplayName("the acceptance record cannot be written by the client")
    void theRecordIsNotClientWritable() throws Exception {
        save(body("ai_review_provider", "openai", "ai_review_allow_remote_url", "true"));
        String recorded = settings.get(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_BY);

        assertThat(save(body(
                        "ai_review_risk_acknowledged_by", "somebody-else",
                        "ai_review_risk_acknowledged_at", "1999-01-01T00:00:00Z")))
                .isEqualTo(400);

        // An acknowledgement whose author the acknowledger picks answers nothing an auditor asks.
        assertThat(settings.get(Setting.AI_REVIEW_RISK_ACKNOWLEDGED_BY)).isEqualTo(recorded);
    }
}

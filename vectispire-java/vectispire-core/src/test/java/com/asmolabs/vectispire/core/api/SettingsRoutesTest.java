package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/**
 * Who may write a setting, asked over HTTP.
 *
 * <p><b>Why this exists.</b> {@code AuthorizationCoverageTest} exempts {@code SettingsController}
 * by name — correctly, since it serves nothing belonging to a scan target — and the exemption
 * takes the whole file with it, every route added later included. So the only thing standing
 * between a plain reader and the account's tracker token was one annotation with nothing behind
 * it: deleting {@code @RequiresAdministrator} from the route that writes the model provider key
 * left the entire {@code vectispire-core} suite green. That is the shape of defect this project
 * has already shipped three times — a control that works, and an assertion that cannot notice when
 * it stops.
 *
 * <p><b>Through the filter chain, not by calling the controller.</b> A direct call proves the
 * method body; the annotation is enforced by the chain, so a direct call is exactly the test that
 * cannot see this. {@link ApiTestBase} assembles the real one.
 */
@DisplayName("the settings routes")
class SettingsRoutesTest extends ApiTestBase {

    /** Every writing route, with a body each will accept if it gets that far. */
    private static Map<String, String> writingRoutes() {
        return Map.of(
                "/api/v1/settings", "{\"eol_warn_days\":\"30\"}",
                "/api/v1/settings/ticket-token", "{\"token\":\"probe\"}",
                "/api/v1/settings/webhook-secret", "{\"secret\":\"probe\"}",
                "/api/v1/settings/ticket-webhook-secret", "{\"secret\":\"probe\"}",
                "/api/v1/settings/ai-openai-key", "{\"secret\":\"probe\"}");
    }

    @Test
    @DisplayName("a plain account may read the catalog and write none of it")
    void aReaderWritesNothing() throws Exception {
        String reader = asReader();

        for (Map.Entry<String, String> route : writingRoutes().entrySet()) {
            int status = mvc.perform(authenticated(put(route.getKey()), reader)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(route.getValue()))
                    .andReturn().getResponse().getStatus();

            assertThat(status)
                    .as("PUT %s answered %d to an ordinary account. Every route here writes "
                            + "deployment configuration, and three of them write a credential — a "
                            + "reader clearing the tracker token stops ticket creation estate-wide, "
                            + "and a reader setting one points it at their own tracker",
                            route.getKey(), status)
                    .isEqualTo(403);
        }
    }

    @Test
    @DisplayName("an administrator may write all of it")
    void anAdministratorWritesAll() throws Exception {
        String admin = asAdmin();

        for (Map.Entry<String, String> route : writingRoutes().entrySet()) {
            int status = mvc.perform(authenticated(put(route.getKey()), admin)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(route.getValue()))
                    .andReturn().getResponse().getStatus();

            // The counterpart the refusal above needs to mean anything: a rule that refuses
            // everybody is not an authorization rule, and would pass the test above forever.
            assertThat(status)
                    .as("PUT %s answered %d to an administrator", route.getKey(), status)
                    .isEqualTo(200);
        }
    }

    @Test
    @DisplayName("the connection test is not a second way to read the endpoint")
    void theConnectionTestRefusesAReader() throws Exception {
        // `ai_review_ollama_url` is marked SECRET so the catalog withholds it from a
        // non-administrator: an internal model endpoint describes the estate's topology, and the
        // setting's own help text calls it the destination that receives source code. This route
        // reports on that endpoint and answers with its URL, so under the class marker alone it
        // handed a reader the value withheld four lines away — verified before it was narrowed.
        int status = mvc.perform(authenticated(post("/api/v1/settings/ollama-test"), asReader()))
                .andReturn().getResponse().getStatus();

        assertThat(status)
                .as("the connection test answered %d to an ordinary account; it reports the "
                        + "configured URL and makes the server dial it", status)
                .isEqualTo(403);
    }
}

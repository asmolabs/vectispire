package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What the security chain does with paths that are not the API.
 *
 * <p>Serving the interface from the same jar means the chain now sees two kinds of request it
 * never saw before, and both have a failure mode that looks like something else:
 *
 * <ul>
 *   <li>the bundle itself must be reachable <b>without a token</b> — it is the code that asks
 *       for one, and requiring one first means the sign-in screen answers 401 and nobody can
 *       ever sign in;
 *   <li>an unmapped path under <b>{@code /api} must stay a 404</b>. Forwarding it to
 *       {@code index.html} would answer every mistyped endpoint with an HTML page, and a client
 *       would report a parse error instead of a missing route.
 * </ul>
 *
 * <p>These run without the interface bundled — {@code -Pui} is off in the test build — which is
 * exactly the case worth pinning: the rules must be harmless when there is no {@code static/}.
 */
@DisplayName("serving the interface beside the API")
class BundledInterfaceTest extends ApiTestBase {

    @Test
    @DisplayName("an unmapped API path stays a 404, and never becomes a page")
    void apiPathsAreNotForwarded() throws Exception {
        // 404 and not 401: the caller is anonymous, but the rule that matters here is that
        // `/api` is excluded from the SPA pattern. A 401 would mean the exclusion works; a 200
        // would mean it does not and the client just received HTML.
        mvc.perform(authenticated(get("/api/v1/no-such-endpoint"), asAdmin()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("an anonymous request for a deep link is not refused")
    void deepLinksAreNotRefusedToAnonymous() throws Exception {
        // 404 here because nothing is bundled in the test build — the point is that it is *not*
        // 401. A refusal would mean somebody needs a token to load the screen that asks for one.
        mvc.perform(get("/security")).andExpect(status().isNotFound());
        mvc.perform(get("/")).andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("an anonymous API call is still refused")
    void theApiIsStillClosed() throws Exception {
        // The rule above must not have opened anything: the SPA pattern excludes `/api/`, so
        // this is the check that the exclusion is real and not merely written down.
        mvc.perform(get("/api/v1/issues")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/users")).andExpect(status().isUnauthorized());
    }
}

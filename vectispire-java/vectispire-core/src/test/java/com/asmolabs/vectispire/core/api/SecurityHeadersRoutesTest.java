package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The response headers the architecture documents promise.
 *
 * <p><b>Written because the policy was correct in the source and asserted nowhere</b> — the same
 * gap that let a CPU quota be documented for weeks while no code applied one. A directive deleted
 * from {@code SecurityConfiguration} would have broken nothing any test could see.
 */
@DisplayName("the security response headers")
class SecurityHeadersRoutesTest extends ApiTestBase {

    @Test
    @DisplayName("the content security policy reaches a response")
    void policyIsSent() throws Exception {
        // `default-src 'self'` is the floor; `object-src 'none'` and `frame-ancestors 'none'` stop
        // a plugin and a clickjacking frame respectively, and neither has a default worth relying
        // on.
        mvc.perform(authenticated(get("/api/v1/issues"), asReader()))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy",
                        Matchers.allOf(
                                Matchers.containsString("default-src 'self'"),
                                Matchers.containsString("script-src 'self'"),
                                Matchers.containsString("object-src 'none'"),
                                Matchers.containsString("base-uri 'self'"),
                                Matchers.containsString("frame-ancestors 'none'"))));
    }

    @Test
    @DisplayName("script-src never gains unsafe-inline, which would make the policy decorative")
    void scriptSrcStaysStrict() throws Exception {
        String policy = mvc.perform(authenticated(get("/api/v1/issues"), asReader()))
                .andReturn().getResponse().getHeader("Content-Security-Policy");

        // `style-src` carries `unsafe-inline` because Angular emits inline styles, and that is a
        // bounded concession. The same word in `script-src` would undo the rest of the policy,
        // and it is exactly the change nothing would otherwise catch.
        org.assertj.core.api.Assertions.assertThat(policy).isNotNull();
        String scriptSrc = java.util.Arrays.stream(policy.split(";"))
                .map(String::trim)
                .filter(directive -> directive.startsWith("script-src"))
                .findFirst()
                .orElseThrow();
        org.assertj.core.api.Assertions.assertThat(scriptSrc).doesNotContain("unsafe-inline");
    }

    @Test
    @DisplayName("an unauthenticated call is 401 with no browser challenge")
    void noBasicAuthChallenge() throws Exception {
        // A `WWW-Authenticate` header would make a browser pop a credential dialog over a token
        // API, which helps nobody and trains people to type passwords into prompts.
        mvc.perform(get("/api/v1/issues"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist("WWW-Authenticate"));
    }
}

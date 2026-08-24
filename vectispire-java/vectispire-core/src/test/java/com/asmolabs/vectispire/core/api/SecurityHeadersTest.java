package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The headers a browser is handed, checked rather than described.
 *
 * <p><b>Why this suite exists at all.</b> The content security policy was written in
 * {@code docs/architecture/03-security.md} for an implementation that was then rewritten, and
 * the header disappeared with it — the document went on describing a control the server did not
 * send, and nothing anywhere disagreed. That is the failure mode of a security header: absence
 * changes nothing visible. Every page still renders, every call still works, and the only
 * difference is what happens the day a finding's description contains a {@code <script>}.
 *
 * <p>The assertions below are deliberately literal — the whole policy string, not "contains
 * default-src". A policy that lost {@code script-src} while keeping the header would satisfy a
 * loose assertion, and {@code script-src} is the directive doing the work.
 */
@DisplayName("the security headers")
class SecurityHeadersTest extends ApiTestBase {

    /**
     * The policy, spelled out a second time on purpose.
     *
     * <p>Importing the constant from the configuration would make this test agree with whatever
     * the configuration says, including a relaxation somebody added in passing. Written out
     * here, widening the policy means editing a test that explains what each part is for — which
     * is the conversation that should happen.
     */
    private static final String EXPECTED_POLICY = "default-src 'self'; "
            + "script-src 'self'; "
            + "style-src 'self' 'unsafe-inline'; "
            + "img-src 'self' data:; "
            + "font-src 'self'; "
            + "connect-src 'self'; "
            + "object-src 'none'; "
            + "base-uri 'self'; "
            + "form-action 'self'; "
            + "frame-ancestors 'none'";

    @Test
    @DisplayName("the policy travels with an API response")
    void theApiCarriesThePolicy() throws Exception {
        mvc.perform(authenticated(get("/api/v1/issues"), asAdmin()))
                .andExpect(header().string("Content-Security-Policy", EXPECTED_POLICY));
    }

    @Test
    @DisplayName("and with a response nobody is authenticated for")
    void anonymousResponsesCarryItToo() throws Exception {
        // The sign-in screen is fetched without a session, and it is the document an injected
        // string would run in. A policy applied only to authenticated responses would guard
        // everything except the page that matters most.
        mvc.perform(get("/api/v1/issues")).andExpect(header().string("Content-Security-Policy", EXPECTED_POLICY));
        mvc.perform(get("/")).andExpect(header().string("Content-Security-Policy", EXPECTED_POLICY));
    }

    @Test
    @DisplayName("script-src grants neither 'unsafe-inline' nor 'unsafe-eval'")
    void scriptsStayStrict() throws Exception {
        // Stated as its own case because this is the half that cannot be traded away. `style-src`
        // carries `'unsafe-inline'` — measured against the running interface, which renders
        // unstyled without it — and a relaxation on styles costs page redressing. The same
        // keyword on `script-src` costs the analyst's session, which is the whole attack.
        String policy = mvc.perform(get("/"))
                .andReturn()
                .getResponse()
                .getHeader("Content-Security-Policy");

        assertThat(policy).isNotNull();
        String scripts = policy.substring(policy.indexOf("script-src"));
        assertThat(scripts.substring(0, scripts.indexOf(';')))
                .doesNotContain("unsafe-inline")
                .doesNotContain("unsafe-eval");
    }

    @Test
    @DisplayName("HSTS is absent, deliberately")
    void noStrictTransportSecurity() throws Exception {
        // Vectispire is routinely reached over plain HTTP on an internal address. A
        // Strict-Transport-Security header seen once makes that origin permanently unreachable
        // in that browser — an outage no operator would connect to a header they never
        // configured. It belongs to the proxy terminating TLS, which knows it has TLS.
        mvc.perform(get("/")).andExpect(header().doesNotExist("Strict-Transport-Security"));
    }
}

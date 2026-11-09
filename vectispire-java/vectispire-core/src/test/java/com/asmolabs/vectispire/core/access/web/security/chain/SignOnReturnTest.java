package com.asmolabs.vectispire.core.access.web.security.chain;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * The requested page across the single sign-on round trip.
 *
 * <p>The start goes through Spring's own redirect filter with the resolver the chain installs, so
 * what is remembered is what the real authorization start remembers, in the session it creates.
 * The callback is not replayed: completing it needs a provider's token endpoint. What is asserted of
 * it is the part that is ours — the redirect the success, refusal and failure handlers all build
 * from that session, whatever the callback's query says.
 */
@DisplayName("the page asked for before single sign-on")
class SignOnReturnTest {

    private final OAuth2AuthorizationRequestRedirectFilter start = new OAuth2AuthorizationRequestRedirectFilter(
            SignOnReturn.remembering(new InMemoryClientRegistrationRepository(ClientRegistration.withRegistrationId("oidc")
                    .clientId("vectispire")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .scope("openid")
                    .authorizationUri("https://idp.example/auth")
                    .tokenUri("https://idp.example/token")
                    .jwkSetUri("https://idp.example/certs")
                    .build())));

    @Test
    @DisplayName("survives the round trip and comes back to the sign-in screen, encoded")
    void survivesTheRoundTrip() throws Exception {
        MockHttpSession session = startWith("/projects/1/checklist?tab=open");

        assertThat(SignOnReturn.loginRedirect(callback(session, null), "sso=complete"))
                .isEqualTo("/login?sso=complete&returnUrl=%2Fprojects%2F1%2Fchecklist%3Ftab%3Dopen");
    }

    @Test
    @DisplayName("is read once: a second callback on the same session has nothing to return to")
    void isReadOnce() throws Exception {
        MockHttpSession session = startWith("/projects/1/checklist");
        SignOnReturn.loginRedirect(callback(session, null), "sso=complete");

        assertThat(SignOnReturn.loginRedirect(callback(session, null), "sso=complete"))
                .isEqualTo("/login?sso=complete");
    }

    @Test
    @DisplayName("is carried by a refusal too, beside its reason")
    void isCarriedByARefusal() throws Exception {
        MockHttpSession session = startWith("/issues");

        assertThat(SignOnReturn.loginRedirect(callback(session, null), "sso=refused&reason=no_account"))
                .isEqualTo("/login?sso=refused&reason=no_account&returnUrl=%2Fissues");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "//evil.example", "/\\evil.example", "https://evil.example", "%2F%2Fevil.example", "/%2F%2Fevil.example",
        "/\t/evil.example", "/login"
    })
    @DisplayName("falls back to the default page for every hostile form")
    void fallsBack(String hostile) throws Exception {
        MockHttpSession session = startWith(hostile);

        assertThat(SignOnReturn.loginRedirect(callback(session, null), "sso=complete"))
                .isEqualTo("/login?sso=complete");
    }

    @Test
    @DisplayName("is never taken from the callback, which cannot override the one remembered")
    void isNeverTakenFromTheCallback() throws Exception {
        MockHttpSession remembered = startWith("/dashboard");
        assertThat(SignOnReturn.loginRedirect(callback(remembered, "/scans/666"), "sso=complete"))
                .isEqualTo("/login?sso=complete&returnUrl=%2Fdashboard");

        MockHttpSession none = startWith(null);
        assertThat(SignOnReturn.loginRedirect(callback(none, "/scans/666"), "sso=complete"))
                .isEqualTo("/login?sso=complete");
    }

    @Test
    @DisplayName("is held to the rule again on the way out, whatever the session holds")
    void isCheckedAgainOnTheWayOut() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(SignOnReturn.ATTRIBUTE, "//evil.example");

        assertThat(SignOnReturn.loginRedirect(callback(session, null), "sso=complete"))
                .isEqualTo("/login?sso=complete");
    }

    @Test
    @DisplayName("is forgotten by a start that names none, so an abandoned attempt chooses nothing")
    void isForgottenByANewStart() throws Exception {
        MockHttpSession session = startWith("/projects/1/checklist");
        startWith(null, session);

        assertThat(SignOnReturn.loginRedirect(callback(session, null), "sso=complete"))
                .isEqualTo("/login?sso=complete");
    }

    @Test
    @DisplayName("is not remembered by a request that starts no authorization")
    void isNotRememberedOutsideTheStart() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequest elsewhere = new MockHttpServletRequest("GET", "/oauth2/other");
        elsewhere.setServletPath("/oauth2/other");
        elsewhere.setSession(session);
        elsewhere.setParameter(SignOnReturn.PARAMETER, "/projects/1");
        start.doFilter(elsewhere, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(session.getAttribute(SignOnReturn.ATTRIBUTE)).isNull();
    }

    private MockHttpSession startWith(String returnUrl) throws Exception {
        return startWith(returnUrl, new MockHttpSession());
    }

    private MockHttpSession startWith(String returnUrl, MockHttpSession session) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorization/oidc");
        request.setServletPath("/oauth2/authorization/oidc");
        request.setSession(session);
        if (returnUrl != null) {
            request.setParameter(SignOnReturn.PARAMETER, returnUrl);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        start.doFilter(request, response, new MockFilterChain());
        // The real start: a redirect to the provider, and the state it will check held in the session.
        assertThat(response.getRedirectedUrl()).startsWith("https://idp.example/auth?");
        return (MockHttpSession) request.getSession(false);
    }

    private static MockHttpServletRequest callback(HttpSession session, String planted) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/oidc");
        request.setSession(session);
        request.setParameter("code", "c");
        request.setParameter("state", "s");
        if (planted != null) {
            request.setParameter(SignOnReturn.PARAMETER, planted);
        }
        return request;
    }
}

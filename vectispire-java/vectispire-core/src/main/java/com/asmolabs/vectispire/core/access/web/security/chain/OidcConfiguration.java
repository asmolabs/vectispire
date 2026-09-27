package com.asmolabs.vectispire.core.access.web.security.chain;

import com.asmolabs.vectispire.core.access.AuthenticationFlowService;
import com.asmolabs.vectispire.core.access.ExternalIdentityService;
import com.asmolabs.vectispire.core.access.web.security.TrustedProxies;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Optional single sign-on, on top of the accounts Vectispire already has.
 *
 * <h2>Keycloak authenticates; Vectispire still issues the session</h2>
 *
 * <p>The alternative — validating the provider's token on every request, as a resource server —
 * reads as the purer design and costs more. It gives the application two sources of principal,
 * empties the session's absolute and idle lifetimes of meaning, makes the audit trail's identity
 * a claim rather than a row, and does not even remove {@code t_user}: the role and the
 * per-target visibility still have to live somewhere. Here the provider answers one question —
 * who is this — and everything downstream keeps reading the same session row it always read.
 *
 * <h2>Present only when configured</h2>
 *
 * <p>The whole thing hangs on one variable. With no {@code VECTISPIRE_OIDC_ISSUER} there is no
 * registration, no extra filter chain, no extra route and no button: an optional feature that is
 * off should be absent, not present and refusing.
 *
 * <p><b>Password login stays.</b> It is the way in when the realm is unreachable or
 * misconfigured, and without it a broken issuer locks everybody out of a security tool.
 */
@Configuration
// **Conditional on the issuer, not on the registration bean.** `@ConditionalOnBean` is evaluated
// while user configuration is processed, before the auto-configuration that would create a
// registration — so the condition would read false on a correctly configured instance. The
// property is the honest signal, and it also lets the variables follow this project's naming
// rather than Spring's nested property soup.
@ConditionalOnProperty("vectispire.oidc.issuer")
public class OidcConfiguration {

    private static final Logger log = LoggerFactory.getLogger(OidcConfiguration.class);

    /**
     * The one-time cookie that carries the session token from the redirect to the application.
     *
     * <p><b>Not the URL fragment</b>, which is the usual shortcut. A fragment never reaches a
     * server, which is what makes it tempting, but it does reach the browser's history and every
     * extension reading the address bar — and a session token in history outlives the tab. This
     * cookie is host-only, {@code HttpOnly}, {@code SameSite=Lax} so it survives the redirect
     * back from the provider, and is deleted by the exchange that reads it.
     */
    public static final String HANDOFF_COOKIE = "zs_handoff";

    /** Long enough for a redirect and a page load, short enough to be worthless if captured. */
    private static final int HANDOFF_SECONDS = 60;

    /**
     * The provider, built here from Vectispire's own variables.
     *
     * <p>`VECTISPIRE_OIDC_ISSUER` is the realm's issuer URL — the one whose
     * `/.well-known/openid-configuration` describes the rest, so Vectispire discovers the endpoints
     * instead of asking an operator to copy four of them correctly.
     */
    @Bean
    ClientRegistrationRepository oidcProvider(
            @Value("${vectispire.oidc.issuer}") String issuer,
            @Value("${vectispire.oidc.client-id}") String clientId,
            @Value("${vectispire.oidc.client-secret:}") String clientSecret,
            @Value("${vectispire.oidc.name:Single sign-on}") String name) {

        ClientRegistration registration = ClientRegistrations.fromIssuerLocation(issuer)
                .registrationId("oidc")
                .clientId(clientId)
                .clientSecret(clientSecret.isBlank() ? null : clientSecret)
                // Public client when no secret is set: a browser application in a realm that
                // issues none is a normal deployment, and demanding one would be demanding a
                // secret nobody has.
                .clientAuthenticationMethod(clientSecret.isBlank()
                        ? ClientAuthenticationMethod.NONE
                        : ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .scope("openid", "profile", "email")
                .clientName(name)
                .build();

        return new InMemoryClientRegistrationRepository(registration);
    }

    private final TrustedProxies proxies;

    public OidcConfiguration(TrustedProxies proxies) {
        this.proxies = proxies;
    }

    /**
     * <b>Ordered before the API chain</b>, and matching only the sign-on routes.
     *
     * <p>This chain is the one place in the application that is not stateless: the authorization
     * code flow needs a servlet session to hold the state and nonce between the redirect out and
     * the redirect back. It is created here and nowhere else, and it carries no application
     * identity — the identity is the Vectispire session the success handler mints.
     *
     * <p>The flow service arrives here rather than through the constructor: it reads the provider
     * registration this class declares, so a constructor asking for it would ask for itself.
     */
    @Bean
    @Order(1)
    SecurityFilterChain oidcSecurity(HttpSecurity http, AuthenticationFlowService flows) throws Exception {
        return http.securityMatcher("/oauth2/**", "/login/oauth2/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .oauth2Login(login -> login
                        .successHandler(onSuccess(flows))
                        // A refusal goes back to the login screen with a reason, rather than to
                        // a white page whose only content is a stack trace.
                        .failureHandler((request, response, exception) -> {
                            log.warn("Single sign-on failed: {}", exception.getMessage());
                            response.sendRedirect("/login?sso=failed");
                        }))
                .build();
    }

    /**
     * What happens once the provider has vouched for somebody.
     *
     * <p>The sign-in itself — second factor, account, teams, session, audit entry — is {@link
     * AuthenticationFlowService#completeFederatedSignIn}'s, in one transaction; this adapts HTTP to
     * it: the claims out of the token, the client's address from the trusted proxies, the token into
     * a one-time cookie. A refusal is redirected with its reason rather than thrown: the person is in
     * a browser, mid-redirect, and a 500 tells them nothing.
     */
    private AuthenticationSuccessHandler onSuccess(AuthenticationFlowService flows) {
        return (request, response, authentication) -> {
            if (!(authentication.getPrincipal() instanceof OidcUser oidc)) {
                redirectRefused(response, ExternalIdentityService.Refusal.NO_IDENTITY);
                return;
            }

            AuthenticationFlowService.FederatedSignIn outcome = flows.completeFederatedSignIn(
                    new AuthenticationFlowService.FederatedIdentity(
                            oidc.getSubject(),
                            oidc.getIssuer() == null ? null : oidc.getIssuer().toString(),
                            new ExternalIdentityService.Claimed(
                                    oidc.getPreferredUsername(),
                                    oidc.getEmail(),
                                    Boolean.TRUE.equals(oidc.getEmailVerified())),
                            oidc.getClaimAsStringList("amr"),
                            oidc.getClaimAsString("acr"),
                            oidc.getClaimAsStringList("groups")),
                    request.getHeader("User-Agent"),
                    proxies.clientAddress(request));

            switch (outcome) {
                case AuthenticationFlowService.FederatedSignIn.Refused refused ->
                    redirectRefused(response, refused.refusal());
                case AuthenticationFlowService.FederatedSignIn.SignedIn signedIn -> {
                    // The clear token, straight from the mint into the one-time cookie: the row it
                    // belongs to holds only its hash, so this is the sole copy in existence.
                    // The client's leg, not ours: behind a TLS-terminating proxy `isSecure()` is false —
                    // no forward-headers strategy is set — and the session token went out in a cookie
                    // without `Secure`. The trusted proxy's `X-Forwarded-Proto` is what says HTTPS.
                    response.addCookie(handoff(signedIn.issued().token(), proxies.isSecureTransport(request)));
                    // Back to the sign-in screen rather than to the application, and the marker says
                    // why: that screen is where the browser would land anyway — the token is not in
                    // memory yet, so the first API call answers 401 and the interceptor sends it
                    // there. Naming the case turns a bounce into a step, and saves the application
                    // attempting an exchange on every visit to a page nobody signed on from.
                    response.sendRedirect("/login?sso=complete");
                }
            }
        };
    }

    private static Cookie handoff(String token, boolean secure) {
        Cookie cookie = new Cookie(HANDOFF_COOKIE, token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(HANDOFF_SECONDS);
        // `Lax` and not `Strict`: the browser arrives here from the provider's domain, and a
        // strict cookie would not be sent on that navigation — the sign-on would succeed and the
        // application would still show a login screen.
        cookie.setAttribute("SameSite", "Lax");
        // Only over HTTPS in production; a development instance on http would otherwise never
        // receive it back.
        cookie.setSecure(secure);
        return cookie;
    }

    /** A code, never a sentence: the screen shows its own words — see SignInRefusedException. */
    private static void redirectRefused(
            jakarta.servlet.http.HttpServletResponse response, ExternalIdentityService.Refusal refusal)
            throws IOException {
        response.sendRedirect("/login?sso=refused&reason=" + refusal.wireName());
    }
}

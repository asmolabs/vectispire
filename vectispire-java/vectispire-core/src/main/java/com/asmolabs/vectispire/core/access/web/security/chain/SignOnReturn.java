package com.asmolabs.vectispire.core.access.web.security.chain;

import com.asmolabs.vectispire.common.domain.auth.ReturnPath;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * The page a person asked for, carried across the round trip to the provider.
 *
 * <p>Somebody opening a deep link while signed out reached the sign-in screen with a {@code
 * returnUrl}, and the password form honoured it; single sign-on replaced the tab twice and
 * brought them back to {@code /login?sso=complete} with nothing, so they landed on the dashboard.
 *
 * <p><b>Remembered at the start, never read from the callback.</b> The value is taken from the
 * authorization start ({@code /oauth2/authorization/oidc?returnUrl=…}), held to {@link ReturnPath}
 * and kept in the servlet session this chain already creates for the state and nonce — the same
 * session the provider's callback must present, or the code exchange fails. A {@code returnUrl} on
 * the callback is the provider's URL plus whatever an attacker appended, and is ignored. A start
 * without one forgets any earlier one, so an abandoned attempt cannot choose the next one's page.
 */
final class SignOnReturn {

    static final String PARAMETER = "returnUrl";

    static final String ATTRIBUTE = SignOnReturn.class.getName() + ".path";

    private SignOnReturn() {}

    /** Spring's resolver, remembering the return path whenever it starts an authorization. */
    static OAuth2AuthorizationRequestResolver remembering(ClientRegistrationRepository registrations) {
        DefaultOAuth2AuthorizationRequestResolver standard = new DefaultOAuth2AuthorizationRequestResolver(
                registrations, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        return new OAuth2AuthorizationRequestResolver() {
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                return remember(request, standard.resolve(request));
            }

            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId) {
                return remember(request, standard.resolve(request, registrationId));
            }
        };
    }

    private static OAuth2AuthorizationRequest remember(
            HttpServletRequest request, OAuth2AuthorizationRequest started) {
        // Null means this request was not an authorization start: the filter asks on every pass.
        if (started != null) {
            Optional<ReturnPath> path = ReturnPath.parse(request.getParameter(PARAMETER));
            if (path.isPresent()) {
                request.getSession().setAttribute(ATTRIBUTE, path.get().value());
            } else {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    session.removeAttribute(ATTRIBUTE);
                }
            }
        }
        return started;
    }

    /**
     * The sign-in screen's address with the remembered path appended, which is then forgotten.
     *
     * <p>Every outcome carries it — a refusal too, so the password form offered beside the refusal
     * still returns the person where they were going. It is checked again on the way out: the
     * session is ours, but a value that reaches a {@code Location} header is held to the rule at
     * the point it does.
     */
    static String loginRedirect(HttpServletRequest request, String query) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "/login?" + query;
        }
        Object remembered = session.getAttribute(ATTRIBUTE);
        session.removeAttribute(ATTRIBUTE);
        return (remembered instanceof String value ? ReturnPath.parse(value) : Optional.<ReturnPath>empty())
                .map(path -> "/login?" + query + "&" + PARAMETER + "="
                        + URLEncoder.encode(path.value(), StandardCharsets.UTF_8))
                .orElse("/login?" + query);
    }
}

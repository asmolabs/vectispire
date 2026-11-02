package com.asmolabs.vectispire.core.access.web.security.chain;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.auth.Sessions;
import com.asmolabs.vectispire.common.domain.crypto.DerivationsSaturated;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.core.access.ApiKeyAuthService;
import com.asmolabs.vectispire.core.access.AuthService;
import com.asmolabs.vectispire.core.access.SessionView;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.scim.ScimProperties;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Turns one {@code Authorization: Bearer …} header into whoever is behind it.
 *
 * <p>Supports user session tokens, agent API keys, integration API keys (decision 0024, also in
 * {@code X-API-Key}), SCIM 2.0 provisioning tokens and the metrics scrape token.
 */
@Component
public class BearerAuthenticationFilter extends OncePerRequestFilter {

    /** The header an integration may present its key in, instead of {@code Authorization}. */
    public static final String API_KEY_HEADER = "X-API-Key";

    private final AuthService auth;
    private final ApiKeyAuthService apiKeys;
    private final VisibilityService visibility;
    private final Optional<ScimProperties> scimProperties;
    private final Optional<ScrapeTokenProperties> scrapeToken;

    public BearerAuthenticationFilter(
            AuthService auth,
            ApiKeyAuthService apiKeys,
            VisibilityService visibility,
            Optional<ScimProperties> scimProperties,
            Optional<ScrapeTokenProperties> scrapeToken) {
        this.auth = auth;
        this.apiKeys = apiKeys;
        this.visibility = visibility;
        this.scimProperties = scimProperties;
        this.scrapeToken = scrapeToken;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            Optional<VectispirePrincipal> principal;
            try {
                principal = authenticate(header, pathWithinApplication(request));
                if (principal.isEmpty() && header == null) {
                    // `X-API-Key`, the alias the OpenAPI document has always announced. A key only:
                    // a session token or the SCIM token presented there is not looked at.
                    principal = Optional.ofNullable(request.getHeader(API_KEY_HEADER))
                            .filter(value -> !value.isBlank())
                            .flatMap(this::apiKeyPrincipal);
                }
            } catch (DerivationsSaturated saturated) {
                // An API key is verified as a password is, under the same bound (DerivationGate). Out
                // here no exception handler maps it: thrown on, it would be the container's 500. Not
                // anonymous either — the key was not refused, it was not looked at.
                long seconds = Math.max(1, saturated.retryAfter().toSeconds());
                response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(seconds));
                ProblemResponses.write(request, response, HttpStatus.SERVICE_UNAVAILABLE, saturated.getMessage(),
                        Map.of("retryAfterSeconds", seconds));
                return;
            }
            principal.ifPresent(found -> SecurityContextHolder.getContext().setAuthentication(found));
        }
        chain.doFilter(request, response);
    }

    private Optional<VectispirePrincipal> authenticate(String header, String path) {
        Optional<SessionView> session = auth.resolve(header);
        if (session.isPresent()) {
            Optional<UserView> user = auth.activeUserOf(session.get());
            if (user.isEmpty()) {
                auth.revoke(session.get());
                return Optional.empty();
            }
            return Optional.of(VectispirePrincipal.ofUser(user.get(), session.get()));
        }

        // The one reading of the header, shared with the ceiling on refused tokens (Sessions).
        Optional<String> token = Sessions.bearerToken(header);
        if (token.isEmpty()) {
            return Optional.empty();
        }

        // **The SCIM token is a principal on `/scim` and nowhere else.** It is held by the identity
        // provider — a third system, with its own operators and its own breaches — and it
        // authenticated as an unrestricted administrator on every route: the credential that
        // exists to create and deactivate accounts could read the audit log, rewrite the gate
        // policy, issue API keys and change the settings. Elsewhere it is simply not recognised,
        // and falls through to the API-key lookup like any other unknown bearer. `enabled` is
        // honoured too: a token left in the environment of an installation that switched SCIM off
        // authenticated all the same.
        if (scimProperties.isPresent() && isScimPath(path)) {
            ScimProperties props = scimProperties.get().resolved();
            if (props.enabled() && props.token().isPresent()
                    && SecretCipher.secretEquals(token.get(), props.token().get())) {
                return Optional.of(VectispirePrincipal.ofScimClient());
            }
        }

        // **The scrape token is the SCIM token's twin**: a static secret held by a third system — the
        // monitoring — recognised on `/actuator/prometheus` alone and granting that page alone
        // (ActuatorAccess). Anywhere else it is an unknown bearer, refused and counted by the ceiling.
        if (scrapeToken.isPresent() && ActuatorAccess.PROMETHEUS.equals(path)) {
            Optional<String> expected = scrapeToken.get().token();
            if (expected.isPresent() && SecretCipher.secretEquals(token.get(), expected.get())) {
                return Optional.of(VectispirePrincipal.ofMetricsScraper());
            }
        }

        return token.flatMap(this::apiKeyPrincipal);
    }

    /**
     * An agent's key becomes its agent; an integration key becomes its account, narrowed by the key
     * (decision 0024). Either way the principal reaches only the routes that declare it — see
     * {@code CredentialConfinement}.
     */
    private Optional<VectispirePrincipal> apiKeyPrincipal(String token) {
        return apiKeys.resolve(token).flatMap(key -> apiKeys.hasScope(key, ApiKeyScope.AGENT)
                // No credential restriction: the agent protocol reads no visibility, and an agent's
                // key is issued unrestricted — see VisibilityService.of(AgentView).
                ? apiKeys.agentFor(key).map(agent -> VectispirePrincipal.ofAgent(agent, visibility.of(agent)))
                : apiKeys.integrationFor(key).map(VectispirePrincipal::ofIntegration));
    }

    /** The path the application routes on, without the servlet context it may be deployed under. */
    private static String pathWithinApplication(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        return uri == null ? "" : context != null && !context.isEmpty() && uri.startsWith(context)
                ? uri.substring(context.length())
                : uri;
    }

    private static boolean isScimPath(String path) {
        return path.equals("/scim") || path.startsWith("/scim/");
    }
}

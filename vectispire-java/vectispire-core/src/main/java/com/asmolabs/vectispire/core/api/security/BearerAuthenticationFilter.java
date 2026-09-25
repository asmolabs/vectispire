package com.asmolabs.vectispire.core.api.security;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.core.api.scim.ScimProperties;
import com.asmolabs.vectispire.core.persistence.SessionEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.services.ApiKeyAuthService;
import com.asmolabs.vectispire.core.services.AuthService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Turns one {@code Authorization: Bearer …} header into whoever is behind it.
 *
 * <p>Supports user session tokens, agent API keys, and SCIM 2.0 provisioning tokens.
 */
@Component
public class BearerAuthenticationFilter extends OncePerRequestFilter {

    private final AuthService auth;
    private final ApiKeyAuthService apiKeys;
    private final VisibilityService visibility;
    private final Optional<ScimProperties> scimProperties;

    public BearerAuthenticationFilter(
            AuthService auth, ApiKeyAuthService apiKeys, VisibilityService visibility) {
        this(auth, apiKeys, visibility, Optional.empty());
    }

    @Autowired
    public BearerAuthenticationFilter(
            AuthService auth,
            ApiKeyAuthService apiKeys,
            VisibilityService visibility,
            Optional<ScimProperties> scimProperties) {
        this.auth = auth;
        this.apiKeys = apiKeys;
        this.visibility = visibility;
        this.scimProperties = scimProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            authenticate(header, pathWithinApplication(request)).ifPresent(principal ->
                    SecurityContextHolder.getContext().setAuthentication(principal));
        }
        chain.doFilter(request, response);
    }

    private Optional<VectispirePrincipal> authenticate(String header, String path) {
        Optional<SessionEntity> session = auth.resolve(header);
        if (session.isPresent()) {
            Optional<UserEntity> user = auth.activeUserOf(session.get());
            if (user.isEmpty()) {
                auth.revoke(session.get());
                return Optional.empty();
            }
            return Optional.of(VectispirePrincipal.ofUser(user.get(), session.get()));
        }

        Optional<String> token = bearerToken(header);
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

        return token.flatMap(apiKeys::resolve)
                .filter(key -> apiKeys.hasScope(key, ApiKeyScope.AGENT))
                // No credential restriction: the agent protocol reads no visibility, and an agent's
                // key is issued unrestricted — see VisibilityService.of(AgentEntity). The key's
                // target columns used to be resolved here into a narrowing nothing downstream read.
                .flatMap(key -> apiKeys.agentFor(key)
                        .map(agent -> VectispirePrincipal.ofAgent(agent, visibility.of(agent))));
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

    /** {@code Bearer zsk…} — the scheme is required, so a bare key does not pass by accident. */
    private static Optional<String> bearerToken(String header) {
        if (header == null) {
            return Optional.empty();
        }
        String[] parts = header.trim().split("\\s+", 2);
        return parts.length == 2 && parts[0].equalsIgnoreCase("bearer")
                ? Optional.of(parts[1])
                : Optional.empty();
    }
}

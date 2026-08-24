package com.asmolabs.vectispire.core.api.security;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.core.api.scim.ScimProperties;
import com.asmolabs.vectispire.core.persistence.SessionEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.Users;
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
    private final Users users;
    private final VisibilityService visibility;
    private final Optional<ScimProperties> scimProperties;

    public BearerAuthenticationFilter(
            AuthService auth, ApiKeyAuthService apiKeys, Users users, VisibilityService visibility) {
        this(auth, apiKeys, users, visibility, Optional.empty());
    }

    @Autowired
    public BearerAuthenticationFilter(
            AuthService auth,
            ApiKeyAuthService apiKeys,
            Users users,
            VisibilityService visibility,
            Optional<ScimProperties> scimProperties) {
        this.auth = auth;
        this.apiKeys = apiKeys;
        this.users = users;
        this.visibility = visibility;
        this.scimProperties = scimProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            authenticate(header).ifPresent(principal ->
                    SecurityContextHolder.getContext().setAuthentication(principal));
        }
        chain.doFilter(request, response);
    }

    private Optional<VectispirePrincipal> authenticate(String header) {
        Optional<SessionEntity> session = auth.resolve(header);
        if (session.isPresent()) {
            Optional<UserEntity> user = users.findById(session.get().getUserId()).filter(UserEntity::getIsActive);
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

        // Check dedicated SCIM bearer token
        if (scimProperties.isPresent()) {
            ScimProperties props = scimProperties.get().resolved();
            if (props.token().isPresent() && SecretCipher.secretEquals(token.get(), props.token().get())) {
                return Optional.of(VectispirePrincipal.ofScimClient());
            }
        }

        return token.flatMap(apiKeys::resolve)
                .filter(key -> apiKeys.hasScope(key, ApiKeyScope.AGENT))
                .flatMap(key -> apiKeys.agentFor(key)
                        .map(agent -> VectispirePrincipal.ofAgent(
                                agent, visibility.restrictionOf(key.getTargetKind(), key.getTargetId()))));
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

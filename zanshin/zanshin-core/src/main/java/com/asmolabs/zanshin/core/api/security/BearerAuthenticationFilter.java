package com.asmolabs.zanshin.core.api.security;

import com.asmolabs.zanshin.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.zanshin.core.persistence.SessionEntity;
import com.asmolabs.zanshin.core.persistence.UserEntity;
import com.asmolabs.zanshin.core.repositories.Users;
import com.asmolabs.zanshin.core.services.ApiKeyAuthService;
import com.asmolabs.zanshin.core.services.AuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Turns one {@code Authorization: Bearer …} header into whoever is behind it.
 *
 * <p><b>One header, two credentials.</b> A session token and an API key arrive the same way,
 * and which one it is can only be decided by trying. The session is tried first because it is
 * the common case; an API key that reached the session lookup costs one indexed miss.
 *
 * <p><b>Never rejects.</b> An unreadable or absent credential leaves the context anonymous and
 * the request continues: the authorization rules decide what anonymous may do, and they are the
 * only place that decision should live. A filter that answered 401 here would also answer it
 * for the login route.
 */
@Component
public class BearerAuthenticationFilter extends OncePerRequestFilter {

    private final AuthService auth;
    private final ApiKeyAuthService apiKeys;
    private final Users users;

    public BearerAuthenticationFilter(AuthService auth, ApiKeyAuthService apiKeys, Users users) {
        this.auth = auth;
        this.apiKeys = apiKeys;
        this.users = users;
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

    private Optional<ZanshinPrincipal> authenticate(String header) {
        Optional<SessionEntity> session = auth.resolve(header);
        if (session.isPresent()) {
            Optional<UserEntity> user = users.findById(session.get().getUserId()).filter(UserEntity::getIsActive);
            if (user.isEmpty()) {
                // The account was deactivated or deleted while the session was running. Revoking
                // here rather than merely refusing is what stops a disabled account's tab going
                // on working until the session's own lifetime runs out.
                auth.revoke(session.get().getToken());
                return Optional.empty();
            }
            return Optional.of(ZanshinPrincipal.ofUser(user.get(), session.get()));
        }

        return bearerToken(header)
                .flatMap(apiKeys::resolve)
                .filter(key -> apiKeys.hasScope(key, ApiKeyScope.AGENT))
                .flatMap(apiKeys::agentFor)
                .map(ZanshinPrincipal::ofAgent);
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

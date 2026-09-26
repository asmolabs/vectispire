package com.asmolabs.vectispire.core.access.web.security;

import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.audit.RequestActor;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Builds the {@link RequestActor} a service audits with, from what the route was handed.
 *
 * <p>Here and not in {@code services}: the principal and the servlet request are HTTP's types, and
 * a service taking either would be a service only a route can call.
 *
 * <p><b>The fallback name is the route's to choose, not this class's.</b> Routes have written
 * {@code null}, {@code "unknown"} and {@code "system"} for a caller with no account, and the
 * principal's own name — {@code agent:…} — in two places. Unifying them would change what existing
 * entries are compared against, so each route still says which one it writes.
 */
public final class RequestActors {

    private RequestActors() {}

    /** Attributed to the signed-in account, or to nobody. */
    public static RequestActor of(VectispirePrincipal principal, HttpServletRequest request) {
        return of(principal, request, null);
    }

    /** Attributed to the signed-in account, or to {@code fallback} when there is none. */
    public static RequestActor of(VectispirePrincipal principal, HttpServletRequest request, String fallback) {
        // An integration key writes in its account's name with the key named beside it (decision 0024).
        String username = principal == null
                ? fallback
                : principal.integration().isPresent()
                        ? principal.getName()
                        : principal.user().map(UserView::username).orElse(fallback);
        return named(username, request);
    }

    /** Attributed to a name the route resolved itself. */
    public static RequestActor named(String username, HttpServletRequest request) {
        return request == null
                ? new RequestActor(username, null, null)
                : new RequestActor(username, request.getRemoteAddr(), request.getHeader("User-Agent"));
    }

    /** From this address, for a service that names the actor from what it authenticated. */
    public static RequestActor unnamed(HttpServletRequest request) {
        return named(null, request);
    }
}

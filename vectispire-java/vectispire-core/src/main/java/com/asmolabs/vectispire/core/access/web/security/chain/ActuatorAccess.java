package com.asmolabs.vectispire.core.access.web.security.chain;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Who may read what Actuator serves beyond the health probe: an administrator, signed in.
 *
 * <p><b>Why the chain decides here, and not a route marker.</b> Every other route states who may
 * call it on its handler, and the MVC interceptors confine the credentials that are not a session —
 * an agent key to the agent protocol, an integration key to the routes accepting its scope — and
 * hold back a session that still owes a password change. None of that reaches Actuator: its
 * endpoints are not handlers of the application's mapping, so {@code /actuator/metrics} and
 * {@code /actuator/info} answered any authenticated principal — a remote agent's key, a pipeline's
 * integration key, the bootstrap account before its password was changed, any plain reader — with
 * the instance's internal structure and volumes.
 *
 * <p>An administrator's own session is what the operations screens run as, and the one credential
 * that is none of those: not a key, not a SCIM token, not a session owing a new password.
 */
final class ActuatorAccess {

    private ActuatorAccess() {}

    static AuthorizationManager<RequestAuthorizationContext> administratorSession() {
        return (authentication, context) -> new AuthorizationDecision(isAdministratorSession(authentication.get()));
    }

    static boolean isAdministratorSession(Authentication authentication) {
        return authentication instanceof VectispirePrincipal principal
                && principal.session().isPresent()
                && principal.user()
                        .filter(user -> !user.mustChangePassword())
                        .map(UserView::role)
                        .flatMap(Role::of)
                        .map(Role::isAdministrative)
                        .orElse(false);
    }
}

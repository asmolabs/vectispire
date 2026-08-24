package com.asmolabs.zanshin.core.api.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Enforces the forced password change <b>on the server</b>, not only on the screen.
 *
 * <p>The flag was set in three places — the bootstrap account, creating a user, an
 * administrator's reset — and read by nobody on the server side. Only the Angular client
 * looked at it, which is not a control: a direct API call ignored it, and the bootstrap
 * password — which lives in the deployment's configuration, in an orchestrator's logs and in a
 * shell history — stayed a fully valid SUPERUSER credential with no expiry.
 */
@Component
public class PasswordChangeInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof ZanshinPrincipal principal)) {
            return true;
        }
        boolean pending = principal.user().map(user -> user.getMustChangePassword()).orElse(false);
        if (!pending || allowsPending(method)) {
            return true;
        }

        throw new PasswordChangeRequiredException();
    }

    private static boolean allowsPending(HandlerMethod method) {
        PasswordChangeGate onMethod = method.getMethodAnnotation(PasswordChangeGate.class);
        if (onMethod != null) {
            return onMethod.allowsPending();
        }
        PasswordChangeGate onClass = method.getBeanType().getAnnotation(PasswordChangeGate.class);
        return onClass != null && onClass.allowsPending();
    }
}

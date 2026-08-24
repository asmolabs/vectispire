package com.asmolabs.vectispire.core.api.security;

/**
 * Raised when an account that owes a password change asks for anything else.
 *
 * <p><b>Its own exception rather than Spring Security's {@code AccessDeniedException}</b>, and
 * the difference is a status code the client acts on. Security translates a denial by asking
 * whether the caller is anonymous; when the answer is no it answers 403, and when anything
 * upstream has left the context looking anonymous it answers 401 instead. The real server took
 * the second path and every non-exempt route replied 401 — which a client reads as "sign in
 * again", so it signs in, receives a token, and is refused again. A loop, and the screen never
 * says why.
 *
 * <p>Mapped to 403 by {@code ApiExceptionHandler}, which does not depend on how a filter chain
 * happens to classify the caller. Found by starting the application and calling it; the
 * MockMvc suite answered 403 for the same request, which is exactly the kind of divergence
 * only a real run can show.
 */
public class PasswordChangeRequiredException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public PasswordChangeRequiredException() {
        super("A password change is required before any other action.");
    }
}

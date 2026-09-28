package com.asmolabs.vectispire.common.domain.errors;

import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * A request refused for the state the server is in, not for what it says: the same request may
 * succeed later, unchanged. Answered 409 with its message.
 *
 * <p><b>A type in the foundation, so an owner below the handler can declare one.</b> The handler
 * maps each conflict by name; a refusal kept in a module's {@code internal} — the OWASP review's —
 * cannot be named from {@code platform} without reaching into that module, so it was named by
 * nobody and every refusal it carried came out a 500. Extending this is how such a refusal says 409
 * without anyone importing it.
 *
 * <p><b>A cause a client can tell apart without reading the sentence.</b> Some routes answer 409 for
 * several reasons that call for different gestures — "somebody changed this since you read it, read it
 * again" is not "this is not a draft any more" nor "a second person has to do it". The sentence is
 * written for a person and changes with its wording; a client that branched on it would break on the
 * next edit. A conflict may therefore name its cause, a short token the problem's {@code type} ends
 * with ({@code urn:vectispire:problem:<cause>}), stated for each route in the API's description.
 */
public class ConflictException extends RuntimeException {

    /** A lowercase token of letters, digits and hyphens: what a URN's last segment reads without escaping. */
    private static final Pattern CAUSE = Pattern.compile("[a-z0-9]+(?:-[a-z0-9]+)*");

    private final String cause;

    public ConflictException(String message) {
        super(message);
        this.cause = null;
    }

    /** @param cause the token naming why, which the problem's {@code type} carries */
    protected ConflictException(String message, String cause) {
        super(message);
        Objects.requireNonNull(cause, "cause");
        if (!CAUSE.matcher(cause).matches()) {
            throw new IllegalArgumentException("A conflict's cause is a lowercase token: " + cause);
        }
        this.cause = cause;
    }

    /** The token naming the cause, when the conflict states one. */
    public Optional<String> conflictCause() {
        return Optional.ofNullable(cause);
    }
}

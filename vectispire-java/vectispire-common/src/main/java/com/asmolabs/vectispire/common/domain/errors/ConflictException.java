package com.asmolabs.vectispire.common.domain.errors;

/**
 * A request refused for the state the server is in, not for what it says: the same request may
 * succeed later, unchanged. Answered 409 with its message.
 *
 * <p><b>A type in the foundation, so an owner below the handler can declare one.</b> The handler
 * maps each conflict by name; a refusal kept in a module's {@code internal} — the OWASP review's —
 * cannot be named from {@code platform} without reaching into that module, so it was named by
 * nobody and every refusal it carried came out a 500. Extending this is how such a refusal says 409
 * without anyone importing it.
 */
public class ConflictException extends RuntimeException {

    public ConflictException(String message) {
        super(message);
    }
}

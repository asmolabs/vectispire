package com.asmolabs.vectispire.common.domain.errors;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
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
 *
 * <p><b>And what the sentence names, as data.</b> A cause may come with members of the problem beside
 * {@code detail} (RFC 9457 §3.2, extension members): "revision 3 cannot be submitted: line 2
 * unanswered" names its lines in English prose, which a client in another language cannot point at
 * without parsing it. The members carry the same facts in a shape a client reads — the checklist's
 * incomplete lines, by item. They are written as they are given, so a member is a value a client may
 * see: nothing a refusal would not say in its sentence.
 */
public class ConflictException extends RuntimeException {

    /** A lowercase token of letters, digits and hyphens: what a URN's last segment reads without escaping. */
    private static final Pattern CAUSE = Pattern.compile("[a-z0-9]+(?:-[a-z0-9]+)*");

    /** RFC 9457's own members, which an extension must not overwrite. */
    private static final Set<String> RESERVED = Set.of("type", "title", "status", "detail", "instance");

    private final String cause;

    private final Map<String, Object> members;

    public ConflictException(String message) {
        super(message);
        this.cause = null;
        this.members = Map.of();
    }

    /** @param cause the token naming why, which the problem's {@code type} carries */
    protected ConflictException(String message, String cause) {
        this(message, cause, Map.of());
    }

    /**
     * @param cause the token naming why, which the problem's {@code type} carries
     * @param members extension members of the problem, by name — never {@code type}, {@code title},
     *     {@code status}, {@code detail} or {@code instance}, which the problem's own fields hold
     */
    protected ConflictException(String message, String cause, Map<String, ?> members) {
        super(message);
        Objects.requireNonNull(cause, "cause");
        if (!CAUSE.matcher(cause).matches()) {
            throw new IllegalArgumentException("A conflict's cause is a lowercase token: " + cause);
        }
        members.keySet().stream().filter(RESERVED::contains).findFirst().ifPresent(name -> {
            throw new IllegalArgumentException("\"" + name + "\" is a problem's own field, not an extension member.");
        });
        this.cause = cause;
        this.members = Map.copyOf(new LinkedHashMap<>(members));
    }

    /** The problem's extension members, by name; empty for most conflicts. */
    public Map<String, Object> members() {
        return members;
    }

    /** The token naming the cause, when the conflict states one. */
    public Optional<String> conflictCause() {
        return Optional.ofNullable(cause);
    }
}

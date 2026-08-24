package com.asmolabs.vectispire.common.domain.agents;

import java.util.Locale;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Whether the control plane sends this agent a repository's deployment key.
 *
 * <p><b>An authorization decision, and the only thing that decides it.</b> The NestJS
 * dispatcher consulted the transport and not this mode, so an agent declared {@link #LOCAL} —
 * the one deliberately placed on a less protected machine, on the written promise that no key
 * would be sent to it — received the decrypted deployment key of every repository whose scan
 * it claimed. Nothing routed the queue, so it could harvest them all.
 */
public enum CredentialsMode {

    /** The agent uses its own git access. The default, and the recommendation. */
    LOCAL,

    /**
     * The control plane sends a deployment key with each task.
     *
     * <p>A key leaving the control plane is audited on every send — that is the condition on
     * which this mode exists at all — and it is additionally refused over a transport that is
     * neither encrypted nor sealed.
     */
    DELEGATED;

    private final String wireName = name().toLowerCase(Locale.ROOT);

    public String wireName() {
        return wireName;
    }

    /** Whether a key may be decrypted for this agent at all. */
    public boolean deliversCredentials() {
        return this == DELEGATED;
    }

    /**
     * Empty for an unknown value, and the caller must treat that as {@link #LOCAL}.
     *
     * <p>Never as {@code DELEGATED}: an unreadable mode is a row nobody understands, and the
     * safe reading of "I do not know what this agent is allowed" is "not the key".
     */
    public static Optional<CredentialsMode> byWireName(String value) {
        return Stream.of(values()).filter(mode -> mode.wireName.equals(value)).findFirst();
    }
}

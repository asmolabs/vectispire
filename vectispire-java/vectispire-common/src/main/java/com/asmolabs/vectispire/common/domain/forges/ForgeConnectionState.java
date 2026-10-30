package com.asmolabs.vectispire.common.domain.forges;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Whether a forge connection may be used (decision 0040 §2). Derived from the integrations' registry at every
 * read, never stored: the connection's row does not change when a governor switches its forge off, so that
 * switching it on again resumes it with nothing to redo.
 *
 * <ul>
 *   <li>{@link #ACTIVE} — its forge's integration is enabled;
 *   <li>{@link #SUSPENDED} — its forge's integration is disabled: the row and the encrypted token are kept, and
 *       no discovery, no import, no change-review reading and no probe of its token goes out. A checklist line it
 *       fed reads no data, {@code forge_integration_disabled}.
 * </ul>
 */
public enum ForgeConnectionState {
    ACTIVE("active"),
    SUSPENDED("suspended");

    private final String wireName;

    ForgeConnectionState(String wireName) {
        this.wireName = wireName;
    }

    /** The value the API carries. */
    @JsonValue
    public String wireName() {
        return wireName;
    }

    public static ForgeConnectionState of(boolean integrationEnabled) {
        return integrationEnabled ? ACTIVE : SUSPENDED;
    }
}

package com.asmolabs.vectispire.common.domain.tickets;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Whether the configured tracker may be called (decision 0040 §3). Derived from the integrations' registry at every
 * read, never stored: switching a tracker off writes nothing on the tracker's settings, so that switching it on again
 * resumes it with nothing to redo — as a forge connection's {@code ForgeConnectionState}.
 *
 * <ul>
 *   <li>{@link #ACTIVE} — the tracker's integration is enabled;
 *   <li>{@link #SUSPENDED} — it is disabled: the token, the settings and the links between issues and tickets are
 *       kept, and no ticket is opened or closed, no token is checked and nothing is sent to the tracker.
 * </ul>
 */
public enum TrackerState {
    ACTIVE("active"),
    SUSPENDED("suspended");

    private final String wireName;

    TrackerState(String wireName) {
        this.wireName = wireName;
    }

    /** The value the API carries. */
    @JsonValue
    public String wireName() {
        return wireName;
    }

    public static TrackerState of(boolean integrationEnabled) {
        return integrationEnabled ? ACTIVE : SUSPENDED;
    }
}

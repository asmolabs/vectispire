package com.asmolabs.zanshin.common.domain.agents;

import java.util.Locale;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Where a worker runs.
 *
 * <p>The built-in agent is a row like any other, refreshed on every tick: an operator looking
 * at the agents screen of a quiet system must not see the very process serving them the page
 * reported as offline.
 */
public enum AgentKind {
    /** Inside the process that serves the interface. */
    BUILTIN,

    /** Anywhere else, reaching the control plane by long polling. */
    REMOTE;

    private final String wireName = name().toLowerCase(Locale.ROOT);

    public String wireName() {
        return wireName;
    }

    public static Optional<AgentKind> byWireName(String value) {
        return Stream.of(values()).filter(kind -> kind.wireName.equals(value)).findFirst();
    }
}

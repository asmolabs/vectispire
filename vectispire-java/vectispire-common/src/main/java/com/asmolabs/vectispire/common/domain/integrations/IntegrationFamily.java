package com.asmolabs.vectispire.common.domain.integrations;

/**
 * What kind of outside system an integration talks to (decision 0040). The family is the first segment
 * of every integration's key, which is what keeps {@code gitlab} the forge and {@code gitlab} the
 * tracker two switches rather than one.
 */
public enum IntegrationFamily {
    FORGE("forge", true),
    SIEM("siem", true),
    /** Lot I5 is not built: nothing of the AI review asks the registry before it calls a model. */
    AI("ai", false),
    /** The notification half of lot I6 is not built: no channel asks the registry before it sends. */
    NOTIFICATION("notification", false),
    TRACKER("tracker", true);

    private final String wireName;
    private final boolean suspendable;

    IntegrationFamily(String wireName, boolean suspendable) {
        this.wireName = wireName;
        this.suspendable = suspendable;
    }

    /** The key's first segment and the form the API answers. Stored in every key: it does not move. */
    public String wireName() {
        return wireName;
    }

    /**
     * Whether this version's adapters of the family stop when their integration is disabled — "disabled is
     * unreachable" (0040 §1) holds for them.
     *
     * <p><b>A family that does not is refused the switch-off</b> ({@link IntegrationNotSwitchableException}),
     * never accepted. The registry recorded and audited a disabled AI provider while the review went on
     * sending the code to it: a governor reading the list, an auditor reading the entry, both believed a
     * guarantee no line of code kept. Turn this on in the lot that makes the family's every entry ask the
     * registry, not before.
     */
    public boolean suspendable() {
        return suspendable;
    }
}

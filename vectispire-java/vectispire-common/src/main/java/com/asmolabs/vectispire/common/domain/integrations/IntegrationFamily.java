package com.asmolabs.vectispire.common.domain.integrations;

/**
 * What kind of outside system an integration talks to (decision 0040). The family is the first segment
 * of every integration's key, which is what keeps {@code gitlab} the forge and {@code gitlab} the
 * tracker two switches rather than one.
 */
public enum IntegrationFamily {
    FORGE("forge"),
    SIEM("siem"),
    AI("ai"),
    NOTIFICATION("notification"),
    TRACKER("tracker");

    private final String wireName;

    IntegrationFamily(String wireName) {
        this.wireName = wireName;
    }

    /** The key's first segment and the form the API answers. Stored in every key: it does not move. */
    public String wireName() {
        return wireName;
    }
}

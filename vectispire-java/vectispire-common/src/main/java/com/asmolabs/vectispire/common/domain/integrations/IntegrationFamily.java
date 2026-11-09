package com.asmolabs.vectispire.common.domain.integrations;

/**
 * What kind of outside system an integration talks to (decision 0040). The family is the first segment
 * of every integration's key, which is what keeps {@code gitlab} the forge and {@code gitlab} the
 * tracker two switches rather than one.
 *
 * <p><b>Every family's adapters ask the registry</b>, so every integration may be switched off — unless
 * what its owner reports is still using it ({@link IntegrationInUseException}). Until lots I5 and I6 the AI
 * providers and the notification channels were refused the switch-off ({@code integration-not-switchable}):
 * recorded and audited, a disabled provider would have gone on receiving the findings, because nothing of
 * the review asked. A family added later is wired in the same change that lists it, or the list shows a
 * suspension nothing honours.
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

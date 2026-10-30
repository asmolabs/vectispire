package com.asmolabs.vectispire.common.domain.ticketing;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Supported incident management and issue tracking providers.
 */
public enum TicketingProvider {
    JIRA("Jira Software"),
    GITHUB("GitHub Issues"),
    GITLAB("GitLab Issues");

    private final String displayName;

    TicketingProvider(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * The tracker this provider's tickets live in, whose integration the governor switches (decision 0040 §3). A
     * switch rather than a lookup by name, so that a provider added here without a tracker does not compile.
     */
    public TicketProvider tracker() {
        return switch (this) {
            case JIRA -> TicketProvider.JIRA;
            case GITHUB -> TicketProvider.GITHUB;
            case GITLAB -> TicketProvider.GITLAB;
        };
    }

    /**
     * The provider a request names, in any case.
     *
     * <p>Refused in words rather than by {@code valueOf}, whose "No enum constant
     * com.asmolabs.….TicketingProvider.X" reached the client as the 400's detail — and, once an
     * unmapped {@code IllegalArgumentException} stopped being a 400, would have been a 500.
     */
    public static TicketingProvider parse(String value) {
        for (TicketingProvider provider : values()) {
            if (provider.name().equalsIgnoreCase(value.trim())) {
                return provider;
            }
        }
        throw new InvalidInputException("Unknown ticketing provider \"" + value.trim() + "\". Expected one of: "
                + Arrays.stream(values()).map(p -> p.name().toLowerCase(Locale.ROOT)).collect(Collectors.joining(", "))
                + ".");
    }
}

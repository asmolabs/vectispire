package com.asmolabs.vectispire.common.domain.tickets;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/** Where a ticket is opened, if anywhere. */
public enum TicketProvider {
    NONE,
    GITLAB,
    GITHUB,
    JIRA,
    SERVICENOW;

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    public boolean isEnabled() {
        return this != NONE;
    }

    public static Optional<TicketProvider> fromWireName(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values()).filter(p -> p.wireName().equals(normalized)).findFirst();
    }
}

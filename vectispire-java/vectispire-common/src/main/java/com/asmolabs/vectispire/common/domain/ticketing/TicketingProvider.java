package com.asmolabs.vectispire.common.domain.ticketing;

/**
 * Supported incident management and issue tracking providers.
 */
public enum TicketingProvider {
    JIRA("Jira Software", "https://jira.atlassian.com"),
    GITHUB("GitHub Issues", "https://github.com"),
    GITLAB("GitLab Issues", "https://gitlab.com");

    private final String displayName;
    private final String defaultBaseUrl;

    TicketingProvider(String displayName, String defaultBaseUrl) {
        this.displayName = displayName;
        this.defaultBaseUrl = defaultBaseUrl;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDefaultBaseUrl() {
        return defaultBaseUrl;
    }
}

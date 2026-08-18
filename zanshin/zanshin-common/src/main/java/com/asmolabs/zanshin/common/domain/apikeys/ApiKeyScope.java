package com.asmolabs.zanshin.common.domain.apikeys;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * What an API key is allowed to do.
 *
 * <p>Declaration order matters: {@link ApiKeys#normalizeScopes} emits scopes in it, so two keys
 * granted the same set store the same string and compare equal.
 */
public enum ApiKeyScope {
    READ(true),
    SCAN(true),
    EXPORT(true),

    /**
     * Running scans as an agent.
     *
     * <p><b>Never granted implicitly.</b> It is the scope that lets a holder execute work on
     * Zanshin's behalf, and a default that includes it turns "I issued a read key" into
     * something else entirely.
     */
    AGENT(false);

    private final boolean grantedByDefault;

    ApiKeyScope(boolean grantedByDefault) {
        this.grantedByDefault = grantedByDefault;
    }

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * The defaults, which stay broad on purpose.
     *
     * <p>A form whose defaults break the caller's pipeline mostly teaches them to tick
     * everything. Narrowing is offered, not imposed.
     */
    public static List<ApiKeyScope> defaults() {
        return Arrays.stream(values()).filter(scope -> scope.grantedByDefault).toList();
    }

    public static Optional<ApiKeyScope> fromWireName(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values()).filter(scope -> scope.wireName().equals(normalized)).findFirst();
    }
}

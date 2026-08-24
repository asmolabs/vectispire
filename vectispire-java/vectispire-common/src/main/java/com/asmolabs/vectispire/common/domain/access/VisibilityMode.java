package com.asmolabs.vectispire.common.domain.access;

import java.util.Locale;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * How much a non-administrator sees.
 *
 * <p>An enum rather than a boolean, because the two states already read badly as one — "restrict
 * = false" is the permissive case, and a negated flag is how somebody eventually enables the
 * wrong one. It also leaves room for a third answer without changing the column.
 */
public enum VisibilityMode {

    /** Every signed-in account sees every target. The default, so an update changes nothing. */
    EVERYONE,

    /**
     * An account sees only what an administrator assigned to it.
     *
     * <p>An account with no assignment sees <b>nothing</b>. That is the point: the alternative —
     * "no assignment means no restriction" — makes the safe-looking state the open one, and
     * every account created after the switch would silently see everything.
     */
    ASSIGNED;

    private final String wireName = name().toLowerCase(Locale.ROOT);

    public String wireName() {
        return wireName;
    }

    /**
     * An unreadable value reads as {@link #ASSIGNED}, not as {@link #EVERYONE}.
     *
     * <p>The stricter reading on purpose: a typo in the settings table must not quietly open the
     * deployment. It is the one direction in which failing closed costs a support call and
     * failing open costs a disclosure.
     */
    public static VisibilityMode of(String value) {
        return byWireName(value).orElse(ASSIGNED);
    }

    public static Optional<VisibilityMode> byWireName(String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        return Stream.of(values()).filter(mode -> mode.wireName.equals(normalized)).findFirst();
    }
}

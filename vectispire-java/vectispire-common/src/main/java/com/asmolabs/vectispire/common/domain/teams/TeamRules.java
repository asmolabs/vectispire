package com.asmolabs.vectispire.common.domain.teams;

import java.util.Locale;
import java.util.Set;

/**
 * What a team may be called, and what a team may own.
 *
 * <p>Pure and in the domain, like {@code AccountRules}: these are rules about the vocabulary of
 * access, and they would still hold if Vectispire changed database. Keeping them here is also what
 * lets the interesting cases — a name that is only whitespace, a target kind from a future
 * version — be tested without a server.
 *
 * <p><b>Throwing rather than returning a message, unlike {@code AccountRules}.</b> Those rules
 * feed a form that shows several messages at once, so they return them. These are called from
 * one place each, on a value that is either usable or not, and an {@code Optional} nobody looks
 * at is how an invalid name reaches the database.
 */
public final class TeamRules {

    private TeamRules() {}

    public static final int MAX_NAME_LENGTH = 100;
    public static final int MAX_DESCRIPTION_LENGTH = 255;

    /** The two kinds that exist. Anything else grants nothing, so it is refused on the way in. */
    public static final String KIND_REPOSITORY = "repository";

    public static final String KIND_CONTAINER = "container";

    private static final Set<String> KINDS = Set.of(KIND_REPOSITORY, KIND_CONTAINER);

    /**
     * The name, trimmed, or a refusal.
     *
     * <p>Trimmed and not merely checked: {@code "Backend "} and {@code "Backend"} are one team to
     * everybody who reads the screen, and storing both would make the unique constraint — and
     * every administrator looking at the list — disagree with that. The comparison for
     * uniqueness is case-insensitive for the same reason, and it lives in the repository because
     * it is a query.
     */
    public static String validateName(String name) {
        String trimmed = name == null ? "" : name.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("A team name is required.");
        }
        if (trimmed.length() > MAX_NAME_LENGTH) {
            throw new IllegalArgumentException("A team name is at most " + MAX_NAME_LENGTH + " characters.");
        }
        return trimmed;
    }

    /** Trimmed, null when empty: a description of spaces is not a description. */
    public static String trimDescription(String description) {
        if (description == null) {
            return null;
        }
        String trimmed = description.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        return trimmed.length() <= MAX_DESCRIPTION_LENGTH
                ? trimmed
                : trimmed.substring(0, MAX_DESCRIPTION_LENGTH);
    }

    /**
     * One of the two kinds, lowercased, or a refusal.
     *
     * <p><b>Refused rather than stored and ignored.</b> A kind this version does not recognise
     * resolves to no target at all, so the assignment would appear on the screen and grant
     * nothing — an access-control row that lies about what it does, which is worse than an
     * error message.
     */
    public static String validateTargetKind(String kind) {
        String normalized = kind == null ? "" : kind.trim().toLowerCase(Locale.ROOT);
        if (!KINDS.contains(normalized)) {
            throw new IllegalArgumentException(
                    "Unknown target kind \"" + kind + "\". Expected: " + KIND_REPOSITORY + ", " + KIND_CONTAINER + ".");
        }
        return normalized;
    }
}

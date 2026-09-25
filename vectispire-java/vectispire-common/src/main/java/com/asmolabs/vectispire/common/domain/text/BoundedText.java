package com.asmolabs.vectispire.common.domain.text;

import java.util.Optional;

/**
 * A string checked against the column it is going into, before it gets there.
 *
 * <p><b>Why this exists.</b> A value longer than its column is not refused by Hibernate; it is
 * refused by the database at flush, as a {@code DataException} nothing maps, so the caller receives
 * a 500 for what was a typing mistake — and on SQLite, which the HTTP suite runs on, it is not
 * refused at all, because SQLite does not enforce a {@code varchar} length. The defect is therefore
 * invisible to every test that does not run on a deployable engine. Several services had grown a
 * private copy of this check ({@code TeamRules}, {@code ApiKeyAdministrationService}, the ticket
 * reference); the ones that had not were the ones that answered 500.
 *
 * <p><b>Two behaviours, chosen by who typed the value.</b> {@link #required} and {@link #optional}
 * <em>refuse</em>, for what a person entered on a form: truncating a name or a URL silently stores
 * something they did not write, and a URL cut short points somewhere else. {@link #clip}
 * <em>truncates</em>, for what a machine describes about itself or reports — a scanner's purl, an
 * agent's hostname — where refusing would lose a whole scan result, or a heartbeat, over one
 * display field nobody can correct from here.
 *
 * <p><b>Counted in UTF-16 units, which is conservative.</b> MySQL and PostgreSQL measure a
 * {@code varchar(n)} in characters, and a character outside the Basic Multilingual Plane is two
 * units here, so a value accepted by {@link String#length()} always fits. The reverse is not true —
 * two hundred emoji are refused by a 255 column they would have fitted — which is the direction to
 * be wrong in.
 *
 * <p>In the domain rather than in the services because some of the rules that need it are domain
 * rules — what a setting's value may be, what a triage comment may be — and the layering forbids
 * the domain from reaching upwards.
 */
public final class BoundedText {

    private BoundedText() {}

    /**
     * The ceiling for free text stored in a {@code text} column.
     *
     * <p>MySQL's {@code TEXT} holds 65,535 <em>bytes</em>. A UTF-16 unit takes at most three bytes
     * in UTF-8 (a supplementary character is two units and four bytes), so 16,000 units is at most
     * 48,000 bytes and always fits, with room for the prefix a stored comment sometimes gains.
     * PostgreSQL's {@code text} has no such limit, but a comment is displayed and exported, and one
     * that does not fit on MySQL must not be accepted on the other engine either: the two are
     * deployed interchangeably. Sixteen thousand characters is several pages of prose; a
     * justification longer than that is a document, and belongs attached as evidence.
     */
    public static final int TEXT_MAX = 16_000;

    /**
     * Trimmed, present, and no longer than {@code max}, or a refusal naming the field.
     *
     * @param what the field as the person who filled it knows it — "The repository name"
     * @throws IllegalArgumentException blank or too long, with a message meant to be displayed
     */
    public static String required(String value, int max, String what) {
        String trimmed = value == null ? "" : value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(what + " is required.");
        }
        return within(trimmed, max, what);
    }

    /**
     * Trimmed, {@code null} when blank, and no longer than {@code max} otherwise.
     *
     * <p>Blank becomes null rather than the empty string: an empty name and no name read the same
     * to everyone looking at the screen, and storing both would make them compare differently.
     *
     * @throws IllegalArgumentException too long
     */
    public static String optional(String value, int max, String what) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.isEmpty() ? null : within(trimmed, max, what);
    }

    /**
     * The value as given — not trimmed — if it fits, otherwise a refusal.
     *
     * <p>For the values whose whitespace is part of them: a secret, a comment whose indentation
     * the author meant.
     *
     * @throws IllegalArgumentException too long
     */
    public static String within(String value, int max, String what) {
        tooLong(value, max, what).ifPresent(problem -> {
            throw new IllegalArgumentException(problem);
        });
        return value;
    }

    /**
     * The refusal message when the value does not fit, empty when it does or is null.
     *
     * <p>For the callers that report rather than throw — a settings type collects messages.
     */
    public static Optional<String> tooLong(String value, int max, String what) {
        return value != null && value.length() > max
                ? Optional.of(what + " is longer than " + max + " characters.")
                : Optional.empty();
    }

    /**
     * At most {@code max} units, cut on a character boundary; {@code null} stays {@code null}.
     *
     * <p>Never cuts a surrogate pair in half: the lone high surrogate that would be left is not a
     * character in any encoding, and PostgreSQL refuses the row it is in — the failure this method
     * exists to prevent, moved one character along.
     */
    public static String clip(String value, int max) {
        if (value == null || value.length() <= max) {
            return value;
        }
        int end = max;
        if (end > 0 && Character.isHighSurrogate(value.charAt(end - 1))) {
            end--;
        }
        return value.substring(0, end);
    }
}

package com.asmolabs.zanshin.common.domain.issues;

import java.time.Instant;
import java.time.Period;
import java.time.ZoneOffset;
import java.util.Optional;

/**
 * The rules of a triage decision — validation and expiry.
 *
 * <p>In the domain, hence with no database: these are vocabulary rules and date arithmetic,
 * and they can be tested exhaustively. A service then applies the result to a row.
 *
 * <p>The vocabulary is declared here rather than taken from the entities. The layering rule
 * forbids the domain from knowing about persistence, and that is the right direction for the
 * dependency anyway — the VEX vocabulary exists independently of the table that stores it.
 */
public final class Triage {

    private Triage() {}

    /**
     * @param expiresIn a review date, <b>offered and not imposed</b>. Deciding that a component
     *     is simply not present needs no scheduled re-examination, whereas "not reachable in
     *     our configuration" badly does — and only the person deciding knows which of the two
     *     they have just recorded.
     */
    public record Request(
            TriageStatus status,
            String actor,
            VexJustification justification,
            String comment,
            Period expiresIn) {}

    public record Decision(
            TriageStatus status,
            VexJustification justification,
            String comment,
            String triagedBy,
            Instant triagedAt,
            Optional<Instant> expiresAt) {}

    /**
     * Validates a request and computes what has to be written.
     *
     * @param asOf the instant of the decision
     * @throws InvalidTriageException on anything invalid, with a message meant to be displayed
     */
    public static Decision decide(Request request, Instant asOf) {
        if (request.status() == null) {
            throw new InvalidTriageException("A triage decision needs a status.");
        }
        // VEX **requires** a justification for `not_affected` (and exemptions pending approval):
        // without one the statement carries no information, and an exported document containing it would be invalid.
        if ((request.status() == TriageStatus.NOT_AFFECTED || request.status() == TriageStatus.PENDING_APPROVAL)
                && request.justification() == null) {
            throw new InvalidTriageException(
                    "A justification is required for this triage status (VEX requirement).");
        }

        return new Decision(
                request.status(),
                request.justification(),
                blankToNull(request.comment()),
                request.actor(),
                asOf,
                expiryFrom(request.status(), request.expiresIn(), asOf));
    }

    /**
     * A review date, or empty.
     *
     * <p>Returning an issue to {@link TriageStatus#UNDER_REVIEW} clears any expiry: it is
     * already in the queue, and a date to bring it back there would fire on nothing.
     */
    public static Optional<Instant> expiryFrom(TriageStatus status, Period expiresIn, Instant asOf) {
        if (status == TriageStatus.UNDER_REVIEW || expiresIn == null) {
            return Optional.empty();
        }
        // Absent means "no review date". Zero or negative means the caller got their arithmetic
        // wrong, and quietly reading it as "never" would hide the mistake behind a suppression
        // that never expires.
        if (expiresIn.isZero() || expiresIn.isNegative()) {
            throw new InvalidTriageException("The review delay must be at least one day.");
        }

        // Calendar arithmetic, not a fixed number of hours: "in three months" has to land on the
        // same day of the month, and adding 90 × 24 h drifts across a daylight-saving boundary.
        return Optional.of(asOf.atZone(ZoneOffset.UTC).plus(expiresIn).toInstant());
    }

    /**
     * Is a decision past its review date?
     *
     * <p>A suppression is a statement about a context, and contexts change. Without an expiry, a
     * {@code not_affected} placed in January stays authoritative in December — in the VEX
     * document handed to a customer as much as on the dashboard. That is how VEX suppressions
     * rot.
     */
    public static boolean isExpired(TriageStatus status, Instant expiresAt, Instant asOf) {
        if (expiresAt == null || status == TriageStatus.UNDER_REVIEW) {
            return false;
        }
        return !asOf.isBefore(expiresAt);
    }

    /**
     * What an expiry changes — and above all what it does <b>not</b>.
     *
     * <p>The justification and the comment are <em>kept</em>. The decision had a reason, and
     * whoever re-examines it needs to see it: erasing the text turns a scheduled review into an
     * investigation started from scratch, which is how a review date becomes a field people stop
     * filling in. {@code triagedBy} and {@code triagedAt} are kept for the same reason, and
     * because they are the record of who said what — overwriting them erases evidence.
     *
     * <p>Returning the two changed fields rather than mutating an entity is what keeps this
     * function in the domain: the caller owns the row, and this owns the rule.
     */
    public static Expiry expire() {
        return new Expiry(TriageStatus.UNDER_REVIEW, null);
    }

    /** The only two fields an expiry touches. */
    public record Expiry(TriageStatus status, Instant expiresAt) {}

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}

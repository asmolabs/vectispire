package com.asmolabs.vectispire.core.forges.internal;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The change-review reading's bounds (decision 0037, lot G3). A reading is one repository's branch: its settings —
 * three requests at most — its merged changes, a page per hundred, and one request per change for its approvals, so
 * {@code maxChanges} bounds the requests too. Past it the history is cut short and says so, and the line has no data
 * rather than a figure over part of the window. A turn reads until its own bound, on the hourly maintenance thread:
 * what it does not reach is read at the next turn.
 *
 * <p>{@code refresh} is how old a reading is before it is read again: six hours, so that a rule allowing a day
 * ({@code maxAgeDays} 1) is never judged on a reading the schedule let lapse. Configurable so that a test reaches
 * each bound in seconds.
 */
@Component
public class ReviewBounds {

    private final Duration refresh;
    private final Duration claim;
    private final Duration readingDuration;
    private final Duration turnDuration;
    private final int maxReadings;
    private final int maxChanges;
    private final Duration maxRateLimitWait;

    public ReviewBounds(
            @Value("${vectispire.forges.reviews.refresh:6h}") Duration refresh,
            @Value("${vectispire.forges.reviews.claim:15m}") Duration claim,
            @Value("${vectispire.forges.reviews.reading-duration:2m}") Duration readingDuration,
            @Value("${vectispire.forges.reviews.turn-duration:5m}") Duration turnDuration,
            @Value("${vectispire.forges.reviews.max-readings:200}") int maxReadings,
            @Value("${vectispire.forges.reviews.max-changes:500}") int maxChanges,
            @Value("${vectispire.forges.reviews.max-rate-limit-wait:60s}") Duration maxRateLimitWait) {
        this.refresh = refresh;
        this.claim = claim;
        this.readingDuration = readingDuration;
        this.turnDuration = turnDuration;
        this.maxReadings = Math.max(1, maxReadings);
        this.maxChanges = Math.max(1, maxChanges);
        this.maxRateLimitWait = maxRateLimitWait;
    }

    public Duration refresh() {
        return refresh;
    }

    /** How long an instance holds a reading it claimed: longer than a reading, so that it is never read twice at once. */
    public Duration claim() {
        return claim;
    }

    public Duration readingDuration() {
        return readingDuration;
    }

    public Duration turnDuration() {
        return turnDuration;
    }

    public int maxReadings() {
        return maxReadings;
    }

    public int maxChanges() {
        return maxChanges;
    }

    public Duration maxRateLimitWait() {
        return maxRateLimitWait;
    }
}

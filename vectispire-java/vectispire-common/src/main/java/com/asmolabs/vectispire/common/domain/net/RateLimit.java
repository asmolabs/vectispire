package com.asmolabs.vectispire.common.domain.net;

import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Optional;
import java.util.function.Function;

/**
 * What an answer says about a rate limit: whether it is one, and how long it asks the caller to wait
 * (decision 0037 §3 — <em>rate limits are honoured, never raced</em>).
 *
 * <p><b>A 403 is not always a refusal.</b> GitHub answers a spent primary limit with 403 or 429 and {@code
 * X-RateLimit-Remaining: 0}, and a secondary limit with either status and a {@code Retry-After}; GitLab
 * answers 429 with {@code Retry-After} and {@code RateLimit-Reset}. A 403 carrying none of those is the
 * forge refusing the token something — a namespace it cannot read — and reading it as a limit would wait
 * on a refusal that never lifts.
 *
 * <p><b>Which header sets the wait, in order</b>: {@code Retry-After} (seconds, or an HTTP date), the only
 * one meant as an instruction; then {@code X-RateLimit-Reset} (GitHub, epoch seconds); then {@code
 * RateLimit-Reset} — epoch seconds on GitLab, a number of seconds in the IETF draft other servers follow,
 * told apart by size: no delay is thirty years long. A limit that names no wait at all is read as {@link
 * Optional#empty()}, and the caller decides what that costs.
 */
public final class RateLimit {

    /** A value below this is a delay in seconds, above it an instant in epoch seconds (2001-09-09). */
    private static final long EPOCH_THRESHOLD = 1_000_000_000L;

    private RateLimit() {}

    /**
     * Whether this answer is a rate limit rather than a refusal or a failure.
     *
     * @param header the answer's first value of a header, by name in any case
     */
    public static boolean limited(int status, Function<String, Optional<String>> header) {
        if (status == 429) {
            return true;
        }
        if (status != 403) {
            return false;
        }
        return header.apply("retry-after").isPresent()
                || header.apply("x-ratelimit-remaining").map(String::trim).filter("0"::equals).isPresent()
                || header.apply("ratelimit-remaining").map(String::trim).filter("0"::equals).isPresent();
    }

    /**
     * How long the answer asks the caller to wait, from {@code now}: never negative, and empty when no header
     * names a wait the caller can read.
     */
    public static Optional<Duration> waitOf(Function<String, Optional<String>> header, Instant now) {
        Optional<Duration> retryAfter = header.apply("retry-after").flatMap(value -> retryAfter(value.trim(), now));
        if (retryAfter.isPresent()) {
            return retryAfter;
        }
        Optional<Duration> reset = header.apply("x-ratelimit-reset").flatMap(value -> epoch(value.trim(), now));
        if (reset.isPresent()) {
            return reset;
        }
        return header.apply("ratelimit-reset").flatMap(value -> {
            Optional<Long> number = number(value.trim());
            if (number.isEmpty()) {
                return Optional.empty();
            }
            return number.get() >= EPOCH_THRESHOLD ? epoch(value.trim(), now) : Optional.of(Duration.ofSeconds(number.get()));
        });
    }

    private static Optional<Duration> retryAfter(String value, Instant now) {
        Optional<Long> seconds = number(value);
        if (seconds.isPresent()) {
            return Optional.of(Duration.ofSeconds(seconds.get()));
        }
        try {
            Instant at = ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
            return Optional.of(nonNegative(Duration.between(now, at)));
        } catch (DateTimeParseException unreadable) {
            return Optional.empty();
        }
    }

    private static Optional<Duration> epoch(String value, Instant now) {
        return number(value).map(seconds -> nonNegative(Duration.between(now, Instant.ofEpochSecond(seconds))));
    }

    private static Optional<Long> number(String value) {
        if (value.isEmpty() || value.length() > 18 || !value.chars().allMatch(Character::isDigit)) {
            return Optional.empty();
        }
        return Optional.of(Long.parseLong(value));
    }

    private static Duration nonNegative(Duration wait) {
        return wait.isNegative() ? Duration.ZERO : wait;
    }
}

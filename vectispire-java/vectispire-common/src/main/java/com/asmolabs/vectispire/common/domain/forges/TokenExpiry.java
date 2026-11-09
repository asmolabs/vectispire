package com.asmolabs.vectispire.common.domain.forges;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * When a GitLab or GitHub token stops working, as the server reports it, and where that date stands now.
 *
 * <p>Read by the forge connections' probe (decision 0037 §2) and by the tracker integration's token check: one
 * reading of each server's answer, so that a forge connection and the tracker token issued by the same GitLab
 * cannot be told two different expiries.
 */
public final class TokenExpiry {

    /** How long before an expiry it is announced — the forge connections' fourteen days (decision 0037 §2). */
    public static final Duration NOTICE = Duration.ofDays(14);

    /** GitHub's {@code github-authentication-token-expiration}, whose zone has been written as a name and as an offset. */
    private static final List<DateTimeFormatter> GITHUB_FORMATS = List.of(
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z", Locale.ROOT),
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss Z", Locale.ROOT));

    private TokenExpiry() {}

    /**
     * GitLab's {@code expires_at}: a date, the token's last valid day being the one before it — it stops at
     * midnight UTC of that date. Also the reading of a date an administrator declares for a token whose
     * tracker reports none.
     */
    public static Optional<Instant> ofDate(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(LocalDate.parse(value.trim()).atStartOfDay(ZoneOffset.UTC).toInstant());
        } catch (DateTimeParseException unreadable) {
            return Optional.empty();
        }
    }

    /** GitHub's {@code github-authentication-token-expiration} header; empty when absent or unreadable. */
    public static Optional<Instant> ofGithubHeader(String value) {
        if (value == null) {
            return Optional.empty();
        }
        for (DateTimeFormatter format : GITHUB_FORMATS) {
            try {
                return Optional.of(ZonedDateTime.parse(value.trim(), format).toInstant());
            } catch (DateTimeParseException tryNext) {
                // The next format, then nothing.
            }
        }
        return Optional.empty();
    }

    /**
     * Where an expiry stands at {@code now} — the states the forge connections' list shows, in the same
     * window.
     */
    public enum Standing {
        /** No expiry is known: the server reported none, and none was declared. Said, never left blank. */
        UNKNOWN,
        VALID,
        /** Within {@link #NOTICE} of it. */
        SOON,
        EXPIRED;

        public static Standing of(Optional<Instant> expiresAt, Instant now) {
            if (expiresAt.isEmpty()) {
                return UNKNOWN;
            }
            if (!now.isBefore(expiresAt.get())) {
                return EXPIRED;
            }
            return Duration.between(now, expiresAt.get()).compareTo(NOTICE) <= 0 ? SOON : VALID;
        }
    }
}

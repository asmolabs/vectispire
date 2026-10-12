package com.asmolabs.vectispire.core.tickets;

import com.asmolabs.vectispire.common.domain.forges.TokenExpiry;
import com.asmolabs.vectispire.common.domain.forges.TokenExpiry.Standing;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * What is known of the tracker token's life: the expiry the tracker reported, the one an administrator
 * declared, and whether the tracker has stopped accepting it.
 *
 * <p><b>Why it is kept at all.</b> A token that expired — GitLab now forces an expiry, a year at most by
 * default — made the hourly sweep fail on every call, with a line in the server log as the only trace, for as
 * long as nobody looked: no ticket opened, none closed. The expiry is now read when the token is saved and
 * daily after, a refusal by the tracker is recorded when a call meets one, and the settings screen shows both
 * as the forge connections' list shows a connection's (decision 0037 §2): the expiry announced fourteen days
 * ahead, an expired or refused token said so.
 *
 * <p><b>Announced once per change, not once per hour.</b> The standing last announced is kept beside the
 * rest, and the server log is written when it changes — entering the notice window, expiring, being refused,
 * being accepted again — never on every pass that finds it unchanged.
 *
 * <p>Rows of their own, outside the catalog ({@link SettingsService#setInternal}): what the tracker said is
 * not a setting anybody writes.
 */
@Service
public class TrackerTokenState {

    private static final Logger log = LoggerFactory.getLogger(TrackerTokenState.class);

    /** The expiry the tracker reported, an instant; empty when it reported none. Absent: never asked. */
    static final String REPORTED_EXPIRY = "ticket_token_reported_expiry";

    /** {@code <status> <instant>} of the first refusal since the token was last accepted; empty otherwise. */
    static final String REFUSED = "ticket_token_refused";

    /** When the tracker last answered the token check. */
    static final String CHECKED_AT = "ticket_token_checked_at";

    /** The standing last announced, so that it is announced once. */
    static final String ANNOUNCED = "ticket_token_announced";

    private final SettingsService settings;

    public TrackerTokenState(SettingsService settings) {
        this.settings = settings;
    }

    /** Where the known expiry comes from. */
    public enum ExpirySource {
        /** The tracker said, when asked — GitLab's token description, GitHub's response header. */
        REPORTED,
        /** An administrator wrote it ({@link Setting#TICKET_TOKEN_EXPIRES_ON}): Jira and ServiceNow say nothing. */
        DECLARED,
        UNKNOWN;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    /** A tracker that answered a call made with the token by refusing it. */
    public record Refusal(int status, Instant since) {}

    /**
     * Everything known of the token.
     *
     * @param expiresAt the reported expiry, else the declared one
     * @param refused empty while the tracker accepts the token, or has not been asked
     * @param checkedAt when the tracker last answered the check
     */
    public record Health(
            Optional<Instant> expiresAt, ExpirySource expirySource, Optional<Refusal> refused, Optional<Instant> checkedAt) {

        /** What the screen and the log say, the refusal first: a refused token's date no longer matters. */
        public Announcement announcement(Instant now) {
            if (refused.isPresent()) {
                return Announcement.REFUSED;
            }
            return switch (Standing.of(expiresAt, now)) {
                case SOON -> Announcement.EXPIRES_SOON;
                case EXPIRED -> Announcement.EXPIRED;
                case UNKNOWN, VALID -> Announcement.NONE;
            };
        }
    }

    /** What there is to say about the token; {@link #NONE} when nothing is wrong or nothing is known. */
    public enum Announcement {
        NONE, EXPIRES_SOON, EXPIRED, REFUSED;

        String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }
    }

    public Health read() {
        Optional<Instant> reported = instant(internal(REPORTED_EXPIRY));
        Optional<Instant> declared = TokenExpiry.ofDate(settings.get(Setting.TICKET_TOKEN_EXPIRES_ON));
        ExpirySource source = reported.isPresent()
                ? ExpirySource.REPORTED
                : declared.isPresent() ? ExpirySource.DECLARED : ExpirySource.UNKNOWN;
        return new Health(reported.or(() -> declared), source, refusal(internal(REFUSED)), instant(internal(CHECKED_AT)));
    }

    /** When the tracker last answered the check; empty when it never has since the token was set. */
    Optional<Instant> checkedAt() {
        return instant(internal(CHECKED_AT));
    }

    /** The tracker answered the check: what it says of the expiry — nothing, possibly — replaces what it said. */
    void recordReported(Optional<Instant> expiresAt, Instant now) {
        String value = expiresAt.map(Instant::toString).orElse("");
        if (!value.equals(internal(REPORTED_EXPIRY))) {
            settings.setInternal(REPORTED_EXPIRY, value);
        }
        settings.setInternal(CHECKED_AT, now.toString());
    }

    /**
     * The tracker refused the token. The first refusal's date is kept: a refusal met every hour is one change,
     * dated when it began.
     */
    void recordRefused(int status, Instant now) {
        if (internal(REFUSED).isEmpty()) {
            settings.setInternal(REFUSED, status + " " + now);
        }
        announce(now);
    }

    /** A call made with the token succeeded: a refusal recorded before is over. */
    void recordAccepted(Instant now) {
        if (!internal(REFUSED).isEmpty()) {
            settings.setInternal(REFUSED, "");
        }
        announce(now);
    }

    /**
     * A new token, or none: what was known of the previous one says nothing of it. The announcement is forgotten
     * too, so that the new token's own standing is announced.
     */
    void reset() {
        for (String key : new String[] {REPORTED_EXPIRY, REFUSED, CHECKED_AT, ANNOUNCED}) {
            if (settings.internalValue(key).isPresent()) {
                settings.setInternal(key, "");
            }
        }
    }

    /**
     * Writes the server log when what there is to say has changed since it was last said, and records that it
     * was. Called after every change of state, and by the daily check: an expiry that enters the notice window
     * changes nothing stored, only the date.
     *
     * @return what was announced, or empty when it had been already
     */
    Optional<Announcement> announce(Instant now) {
        Health health = read();
        Announcement current = health.announcement(now);
        if (current.wireName().equals(internal(ANNOUNCED).isEmpty() ? Announcement.NONE.wireName() : internal(ANNOUNCED))) {
            return Optional.empty();
        }
        settings.setInternal(ANNOUNCED, current.wireName());
        switch (current) {
            case EXPIRES_SOON -> log.warn("The tracker token expires on {} ({}): replace it before then, or no ticket "
                    + "will be opened or closed.", health.expiresAt().orElseThrow(), health.expirySource().wireName());
            case EXPIRED -> log.warn("The tracker token expired on {} ({}): no ticket is opened or closed until it is "
                    + "replaced.", health.expiresAt().orElseThrow(), health.expirySource().wireName());
            case REFUSED -> log.warn("The tracker refused its token (HTTP {}) since {}: it is expired, revoked or lacks "
                    + "a permission, and no ticket is opened or closed until it is replaced.",
                    health.refused().orElseThrow().status(), health.refused().orElseThrow().since());
            case NONE -> log.info("The tracker token is no longer refused nor about to expire.");
        }
        return Optional.of(current);
    }

    private String internal(String key) {
        return settings.internalValue(key).map(String::trim).orElse("");
    }

    private static Optional<Instant> instant(String value) {
        if (value.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(Instant.parse(value));
        } catch (DateTimeParseException unreadable) {
            return Optional.empty();
        }
    }

    private static Optional<Refusal> refusal(String value) {
        String[] parts = value.split(" ", 2);
        if (parts.length != 2) {
            return Optional.empty();
        }
        try {
            return instant(parts[1]).map(since -> new Refusal(Integer.parseInt(parts[0]), since));
        } catch (NumberFormatException unreadable) {
            return Optional.empty();
        }
    }
}

package com.asmolabs.vectispire.core.tickets;

import com.asmolabs.vectispire.common.domain.forges.TokenExpiry;
import com.asmolabs.vectispire.common.domain.forges.TokenExpiry.Standing;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert;
import com.asmolabs.vectispire.common.domain.notifications.TokenAlert.Notice;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionTemplate;

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
 * rest, and a change — entering the notice window, expiring, being refused, being accepted again — is announced
 * when it happens, never on every pass that finds it unchanged: a line in the server log, and a {@link TokenAlert}
 * published in the transaction that records it as said, which {@code notifications} turns into an audit entry (and
 * through it a SIEM event) and a message on each configured channel. The record is moved by a conditional update
 * ({@link SettingsService#replaceInternal}), so of two instances noticing the same change one announces it.
 *
 * <p><b>Measured against what was last said, whichever token it was said of.</b> A new token forgets what was
 * known of the previous one but not what was announced: a refused token replaced by one that works is announced as
 * working again — the end of the alert somebody received — and a token removed announces nothing.
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

    /** What {@code TokenAlert#reference} names for the tracker: its token's setting. */
    static final String REFERENCE = Setting.TICKET_TOKEN.key();

    private final SettingsService settings;
    private final ApplicationEventPublisher events;

    /**
     * {@code REQUIRES_NEW}: the record that the change was said and what it causes commit together, apart from
     * whatever the caller is doing — the sweep's call to the tracker is no transaction, and must not become one.
     */
    private final TransactionOperations separately;

    @Autowired
    public TrackerTokenState(
            SettingsService settings, ApplicationEventPublisher events, PlatformTransactionManager transactions) {
        this(settings, events, requiresNew(transactions));
    }

    /** With the boundary supplied — {@link TransactionOperations#withoutTransaction()} for a test with no database. */
    public TrackerTokenState(SettingsService settings, ApplicationEventPublisher events, TransactionOperations separately) {
        this.settings = settings;
        this.events = events;
        this.separately = separately;
    }

    private static TransactionTemplate requiresNew(PlatformTransactionManager transactions) {
        TransactionTemplate template = new TransactionTemplate(transactions);
        template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        return template;
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
        public Notice announcement(Instant now) {
            return Notice.of(refused.isPresent(), Standing.of(expiresAt, now));
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
     * A new token, or none: what was known of the previous one says nothing of it. What was announced is kept: the
     * next announcement is measured against it, so that the replacement of a token said to have stopped working is
     * said to work again. Forgetting it, as this did, left the alert somebody received without its end.
     */
    void reset() {
        for (String key : new String[] {REPORTED_EXPIRY, REFUSED, CHECKED_AT}) {
            if (settings.internalValue(key).isPresent()) {
                settings.setInternal(key, "");
            }
        }
    }

    /**
     * Announces what there is to say when it has changed since it was last said, and records that it was. Called
     * after every change of state, and by the daily check: an expiry that enters the notice window changes nothing
     * stored, only the date.
     *
     * <p>Nothing is said while no token is configured: a removed token neither expires nor works again, and the next
     * one is measured against what was said before it.
     *
     * @return what was announced, or empty when it had been already — here or by another instance
     */
    Optional<Notice> announce(Instant now) {
        if (settings.get(Setting.TICKET_TOKEN).isBlank()) {
            return Optional.empty();
        }
        Health health = read();
        Notice current = health.announcement(now);
        Optional<String> stored = settings.internalValue(ANNOUNCED);
        if (stored.isEmpty()) {
            // The conditional update needs a row to arbitrate on; whoever inserts it, it starts as "nothing said".
            settings.storeInternalIfAbsent(ANNOUNCED, "");
            stored = settings.internalValue(ANNOUNCED);
        }
        String expected = stored.orElse("");
        Notice previous = Notice.read(expected);
        if (previous == current) {
            return Optional.empty();
        }
        TokenAlert alert = new TokenAlert(TokenAlert.Credential.TRACKER_TOKEN, REFERENCE, providerLabel(), where(),
                current, previous, health.expiresAt().orElse(null),
                health.refused().map(Refusal::status).orElse(null), health.refused().map(Refusal::since).orElse(null),
                now);
        boolean said = Boolean.TRUE.equals(separately.execute(status -> {
            if (!settings.replaceInternal(ANNOUNCED, expected, current.wireName())) {
                // Another instance said it first, or something else moved since the read: the next turn reads again.
                return false;
            }
            events.publishEvent(alert);
            return true;
        }));
        if (!said) {
            return Optional.empty();
        }
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

    private String providerLabel() {
        return switch (TicketProvider.fromWireName(settings.get(Setting.TICKET_PROVIDER)).orElse(TicketProvider.NONE)) {
            case GITLAB -> "GitLab";
            case GITHUB -> "GitHub";
            case JIRA -> "Jira";
            case SERVICENOW -> "ServiceNow";
            case NONE -> "no tracker";
        };
    }

    /** The tracker, for a reader: its kind and its address — never the token, nor the account it acts as. */
    private String where() {
        String url = settings.get(Setting.TICKET_BASE_URL).trim();
        return url.isEmpty() ? providerLabel() : providerLabel() + " at " + url;
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

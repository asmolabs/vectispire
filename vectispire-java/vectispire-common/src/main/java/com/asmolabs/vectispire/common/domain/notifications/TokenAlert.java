package com.asmolabs.vectispire.common.domain.notifications;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.forges.TokenExpiry.Standing;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

/**
 * An integration token's change of state — the tracker's, or a forge connection's — said once, where it has to be
 * said: the audit log, through it the SIEM, and the notification channels.
 *
 * <p><b>Why it is pushed.</b> A token that expired or was revoked made the tracker's sweep fail on every call, and
 * a forge connection read nothing, with a line in the server log and a word on a screen as the only trace — for as
 * long as nobody opened that screen. The change is now told to whoever is listening, once.
 *
 * <p><b>Published by the module that owns the token, in the transaction that records it as said</b> — {@code
 * tickets} for the tracker, {@code forges} for a connection — and heard by {@code notifications}, which queues the
 * audit entry and one message per channel in that transaction. It is here, beside the payloads it is rendered
 * into, so that neither owner depends on the channels and the channels on neither owner: the same arrangement as
 * {@code SecurityEventRaised}.
 *
 * <p><b>No secret, by construction.</b> Nothing here is the token or a header: the name an administrator gave, the
 * server's label and — for a forge connection — its address, the dates, and the status a server answered. Every
 * message is made of these and of nothing else.
 *
 * @param reference what the audit entry names: {@code ticket_token}, or the connection's identifier
 * @param name the forge connection's name; for the tracker, the provider's label
 * @param where the server, for a reader: {@code GitLab at https://gitlab.example.com} for a forge connection, whose
 *     address is not a secret; the provider's label alone for the tracker, whose address is a secret setting
 * @param notice what there is to say now
 * @param previous what was said before — which tells "works again" from "no longer about to expire"
 * @param expiresAt the known expiry; null when none is known
 * @param refusedStatus the HTTP status the server refused the token with; null unless {@link Notice#REFUSED}
 * @param refusedSince when the refusal began; null unless {@link Notice#REFUSED}
 * @param observedAt when the change was noticed
 */
public record TokenAlert(
        Credential credential,
        String reference,
        String name,
        String where,
        Notice notice,
        Notice previous,
        Instant expiresAt,
        Integer refusedStatus,
        Instant refusedSince,
        Instant observedAt) {

    /** Whose token it is. Stored in the outbox payload, so the names are a data contract. */
    public enum Credential {
        TRACKER_TOKEN("no ticket is opened or closed", "/settings"),
        FORGE_CONNECTION("the connection can neither discover repositories nor read change reviews", "/forge-connections");

        private final String consequence;
        private final String screen;

        Credential(String consequence, String screen) {
            this.consequence = consequence;
            this.screen = screen;
        }

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }

        /** The interface's page where the token is replaced, relative to the deployment's public address. */
        public String screen() {
            return screen;
        }
    }

    /**
     * What there is to say about a token. {@link #NONE} when nothing is wrong or nothing is known — a token whose
     * expiry nobody knows is not announced as expiring.
     *
     * <p>The wire names are stored as "what was last said", in a settings row per token: they must not move.
     */
    public enum Notice {
        NONE, EXPIRES_SOON, EXPIRED, REFUSED;

        public String wireName() {
            return name().toLowerCase(Locale.ROOT);
        }

        /** What a stored value says; absent, blank or unknown is {@link #NONE}, which is what was said of a new token. */
        public static Notice read(String stored) {
            if (stored == null || stored.isBlank()) {
                return NONE;
            }
            for (Notice notice : values()) {
                if (notice.wireName().equals(stored.trim())) {
                    return notice;
                }
            }
            return NONE;
        }

        /** The refusal first: a refused token's date no longer matters. */
        public static Notice of(boolean refused, Standing standing) {
            if (refused) {
                return REFUSED;
            }
            return switch (standing) {
                case SOON -> EXPIRES_SOON;
                case EXPIRED -> EXPIRED;
                case UNKNOWN, VALID -> NONE;
            };
        }

        /** Whether the token no longer works. */
        public boolean stopped() {
            return this == EXPIRED || this == REFUSED;
        }
    }

    /** One operation per event, so that the audit log's hook signals each without its writer naming it. */
    public AuditOperation operation() {
        return switch (notice) {
            case EXPIRES_SOON -> AuditOperation.INTEGRATION_TOKEN_EXPIRING;
            case EXPIRED, REFUSED -> AuditOperation.INTEGRATION_TOKEN_STOPPED;
            case NONE -> AuditOperation.INTEGRATION_TOKEN_RESTORED;
        };
    }

    /** The SIEM event the audit entry stands for: "stopped" above "expires soon", "works again" informational. */
    public SecurityEventType signal() {
        return switch (notice) {
            case EXPIRES_SOON -> SecurityEventType.INTEGRATION_TOKEN_EXPIRING;
            case EXPIRED, REFUSED -> SecurityEventType.INTEGRATION_TOKEN_STOPPED;
            case NONE -> SecurityEventType.INTEGRATION_TOKEN_RESTORED;
        };
    }

    /** Who the token is, in words. */
    public String subject() {
        return switch (credential) {
            case TRACKER_TOKEN -> "The tracker token (" + oneLine(where) + ")";
            case FORGE_CONNECTION -> "The token of forge connection \"" + oneLine(name) + "\" (" + oneLine(where) + ")";
        };
    }

    /** What happened, in a few words — a mail's subject, a card's title. */
    public String headline() {
        return headline(switch (credential) {
            case TRACKER_TOKEN -> "tracker token";
            case FORGE_CONNECTION -> "forge connection \"" + oneLine(name) + "\"";
        });
    }

    /**
     * The headline without the connection's name, for a place where an administrator's text cannot be made inert —
     * Slack's header, a {@code plain_text} object, has no escape of its own.
     */
    public String anonymousHeadline() {
        return headline(switch (credential) {
            case TRACKER_TOKEN -> "tracker token";
            case FORGE_CONNECTION -> "forge connection";
        });
    }

    private String headline(String who) {
        String what = switch (notice) {
            case EXPIRES_SOON -> "token expires soon";
            case EXPIRED -> "token expired";
            case REFUSED -> "token refused";
            case NONE -> previous == Notice.EXPIRES_SOON ? "token no longer about to expire" : "token working again";
        };
        return "Vectispire · " + who + " · " + what;
    }

    /**
     * The sentence every message carries, and the audit entry's description: who, what, since when, and what it
     * stops.
     */
    public String sentence() {
        String consequence = credential.consequence;
        return switch (notice) {
            case EXPIRES_SOON -> subject() + " expires on " + date(expiresAt) + ": replace it before then, or "
                    + consequence + ".";
            case EXPIRED -> subject() + " expired on " + date(expiresAt) + ": " + consequence + " until it is replaced.";
            case REFUSED -> subject() + " is refused by the server" + Optional.ofNullable(refusedStatus)
                    .map(status -> " (HTTP " + status + ")").orElse("") + " since " + date(refusedSince)
                    + ": it is expired, revoked or lacks a permission, and " + consequence + " until it is replaced.";
            case NONE -> previous == Notice.EXPIRES_SOON
                    ? subject() + " is no longer about to expire."
                    : subject() + " works again.";
        };
    }

    private static String date(Instant instant) {
        return instant == null ? "an unknown date" : instant.toString();
    }

    /**
     * A name an administrator typed, on one line. A mail subject is a header, and a line break in it would start
     * another; a chat would render it as a second paragraph the message did not write.
     */
    static String oneLine(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder line = new StringBuilder(value.length());
        value.codePoints().forEach(c -> line.appendCodePoint(Character.isISOControl(c) ? ' ' : c));
        return line.toString().trim();
    }
}

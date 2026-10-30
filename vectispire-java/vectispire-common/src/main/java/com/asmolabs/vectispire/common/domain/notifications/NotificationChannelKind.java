package com.asmolabs.vectispire.common.domain.notifications;

import java.util.Locale;

/**
 * The destinations a scan's delta can be announced to, each configured on the settings screen and
 * delivered from an outbox row of its own (decision 0040, amended: they are integrations the platform
 * governor switches on and off).
 *
 * <p><b>A type, where there was none.</b> The channels were five outbox message types and five settings,
 * and nothing listed them together; the integrations' registry derives its notification entries from
 * this enum, so a sixth channel declared here is in the registry — and arrives disabled — without
 * anybody restating a list. {@code NotificationChannelKindTest} (vectispire-core) holds it to the
 * channels the application actually delivers through, by their outbox type, both ways.
 */
public enum NotificationChannelKind {

    /** The generic JSON POST, global or per team. */
    WEBHOOK("scan_delta"),
    TEAMS("scan_delta_teams"),
    SLACK("scan_delta_slack"),
    DISCORD("scan_delta_discord"),
    MAIL("scan_delta_mail");

    private final String outboxType;

    NotificationChannelKind(String outboxType) {
        this.outboxType = outboxType;
    }

    /** The integration's name in the registry, lowercase: {@code notification.<this>}. */
    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** The outbox {@code message_type} a delivery to this channel is queued under. Stored: it does not move. */
    public String outboxType() {
        return outboxType;
    }
}

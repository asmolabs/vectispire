package com.asmolabs.vectispire.core.notifications.internal;

import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationFamily;
import com.asmolabs.vectispire.common.domain.notifications.NotificationChannelKind;
import com.asmolabs.vectispire.core.notifications.NotificationDestinations;
import com.asmolabs.vectispire.core.settings.Integrations;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * The notifications' answer to the registry (decision 0040 §3, lot I6): a channel with a destination is in use,
 * and the governor may not switch it off.
 *
 * <p><b>Refused rather than suspended</b>, like a SIEM transport and unlike a forge: the scans keep finding,
 * and with the channel off the alerts meant for it would be queued nowhere — every one of them lost in
 * silence, the security lead reading a quiet channel as a quiet estate. Whoever configured it empties it first
 * (the URL, the recipients, a team's own webhook, the reminders), which is a gesture that says what stops.
 *
 * <p>Called inside the switch's transaction, after the integration's row is locked. Every save that configures
 * a channel holds that row in its own transaction ({@link Integrations#holdEnabled}, the settings
 * and a team's webhook alike), so a save still open is waited for and then read.
 */
@Component
class NotificationChannelInUse implements Integrations.InUse {

    private final NotificationDestinations destinations;

    NotificationChannelInUse(NotificationDestinations destinations) {
        this.destinations = destinations;
    }

    @Override
    public Optional<String> use(Integration integration) {
        if (integration.family() != IntegrationFamily.NOTIFICATION) {
            return Optional.empty();
        }
        return Arrays.stream(NotificationChannelKind.values())
                .filter(kind -> Integration.of(kind).equals(integration))
                .findFirst()
                .map(destinations::uses)
                .filter(uses -> !uses.isEmpty())
                .map(NotificationChannelInUse::sentence);
    }

    private static String sentence(List<String> uses) {
        return "it is a channel the alerts are sent to — " + String.join(", ", uses) + ". Empty it first, in the "
                + "notification settings or on the team: the alerts queued for it would otherwise have nowhere to go, "
                + "and be lost in silence.";
    }
}

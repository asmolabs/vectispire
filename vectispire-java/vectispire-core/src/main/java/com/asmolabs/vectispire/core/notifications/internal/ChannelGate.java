package com.asmolabs.vectispire.core.notifications.internal;

import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.common.domain.notifications.NotificationChannelKind;
import com.asmolabs.vectispire.core.outbox.HeldDeliveryException;
import com.asmolabs.vectispire.core.outbox.NotificationChannel;
import com.asmolabs.vectispire.core.settings.Integrations;
import java.util.Arrays;

/**
 * What every notification channel asks the integrations' registry before it sends (decision 0040, lot I6): the
 * one place the answer is turned into a hold, a refusal or a skip, so that five channels do not each say it
 * their own way.
 *
 * <p><b>Asked at the adapter's entry, not by the relay.</b> The relay is one caller among five — the weekly
 * report, the checklist reminders, the token alerts and the test button reach a channel without it — and a
 * gate placed in front of one caller is a gate the next caller goes round.
 */
public final class ChannelGate {

    private ChannelGate() {}

    /** Whether the channel's integration is on. */
    public static boolean isOn(Integrations registry, NotificationChannelKind kind) {
        return registry.isEnabled(Integration.of(kind));
    }

    /**
     * Whether a scan's delta, an alert, a test may go to this channel: its integration on. A channel whose type
     * names no kind would be one no governor could switch off; {@code NotificationChannelKindTest} keeps there
     * being none, and it reads off here rather than on.
     */
    public static boolean isOn(Integrations registry, NotificationChannel channel) {
        return NotificationChannelKind.byOutboxType(channel.type()).map(kind -> isOn(registry, kind)).orElse(false);
    }

    /** The same for a channel a token's alert goes to, by its key — the channel's name in the registry. */
    public static boolean isOn(Integrations registry, AlertChannel channel) {
        return Arrays.stream(NotificationChannelKind.values())
                .filter(kind -> kind.wireName().equals(channel.alertKey()))
                .findFirst()
                .map(kind -> isOn(registry, kind))
                .orElse(false);
    }

    /**
     * What a delivery from the outbox calls first.
     *
     * <p><b>Held, never failed nor abandoned.</b> A row for a disabled channel exists only when something went
     * round the in-use refusal — a row of {@code t_integration} written by hand, or the switch landing between
     * a queue and its relay. Counted as a failure it would be abandoned in four hours, an alert lost to a switch
     * a governor may turn back in a minute; held, it waits uncounted and leaves once the channel is on again —
     * what the SIEM export does with a disabled transport.
     *
     * @throws HeldDeliveryException when the channel's integration is off
     */
    public static void requireDeliverable(Integrations registry, NotificationChannelKind kind) {
        if (!isOn(registry, kind)) {
            throw new HeldDeliveryException("the notification channel \"" + Integration.of(kind).key() + "\" is "
                    + "disabled on this installation: the message waits until the platform governor enables it");
        }
    }

    /**
     * What a send outside the outbox calls first — the weekly report, a reminder, the test button: nothing waits
     * for those, so the refusal is the integration's own, 409 {@code integration-disabled}.
     *
     * @throws IntegrationDisabledException when the channel's integration is off
     */
    public static void requireEnabled(Integrations registry, NotificationChannelKind kind) {
        if (!isOn(registry, kind)) {
            throw new IntegrationDisabledException(Integration.of(kind));
        }
    }
}

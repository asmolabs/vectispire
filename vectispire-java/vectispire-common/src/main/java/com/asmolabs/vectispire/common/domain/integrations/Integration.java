package com.asmolabs.vectispire.common.domain.integrations;

import com.asmolabs.vectispire.common.domain.aireview.AiProvider;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.notifications.NotificationChannelKind;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * One outside system Vectispire may talk to, which the platform governor switches on or off (decision
 * 0040): a forge kind, a SIEM transport, an AI provider, a notification channel or a tracker.
 *
 * <p><b>The registry is derived, never restated.</b> {@link #all()} reads the enums each adapter is
 * chosen by — {@link ForgeKind}, {@link SiemProtocol}, {@link AiProvider}, {@link NotificationChannelKind},
 * {@link TicketProvider} — so a value added to one of them is an integration the moment it compiles. It
 * then has no row in {@code t_integration} and reads <em>disabled</em> until a governor enables it: an
 * upgrade never widens what an installation reaches without a gesture (0040 §5).
 *
 * <p><b>The key is a contract.</b> {@code <family>.<name>}, lowercase — {@code forge.gitlab}, {@code
 * siem.syslog_tls}. It is the stored row's identity, the route's path and what an audit entry and a
 * refusal name; renaming one would silently turn an integration a governor enabled into a new one that
 * reads disabled. The name is each enum's own stored or wire form, which has the same reason not to move.
 *
 * @param family what kind of system it is, the key's first segment
 * @param name the adapter's name within its family, the key's second segment
 */
public record Integration(IntegrationFamily family, String name) {

    /** Lowercase letters, digits and underscores: what a URL path segment and a column carry unescaped. */
    private static final Pattern NAME = Pattern.compile("[a-z0-9]+(?:_[a-z0-9]+)*");

    /** The longest key the column holds, {@code integration_key varchar(64)}. */
    public static final int MAX_KEY_LENGTH = 64;

    public Integration {
        Objects.requireNonNull(family, "family");
        if (name == null || !NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("An integration's name is a lowercase token: " + name);
        }
        if (family.wireName().length() + 1 + name.length() > MAX_KEY_LENGTH) {
            throw new IllegalArgumentException("An integration's key is at most " + MAX_KEY_LENGTH + " characters: " + name);
        }
    }

    /** {@code <family>.<name>}: what the row, the route and the audit entry name. */
    public String key() {
        return family.wireName() + "." + name;
    }

    public static Integration of(ForgeKind kind) {
        return new Integration(IntegrationFamily.FORGE, kind.wireName());
    }

    public static Integration of(SiemProtocol protocol) {
        return new Integration(IntegrationFamily.SIEM, protocol.name().toLowerCase(Locale.ROOT));
    }

    public static Integration of(AiProvider provider) {
        return new Integration(IntegrationFamily.AI, provider.wireName());
    }

    public static Integration of(NotificationChannelKind channel) {
        return new Integration(IntegrationFamily.NOTIFICATION, channel.wireName());
    }

    /**
     * The tracker a provider names.
     *
     * @throws IllegalArgumentException for {@link TicketProvider#NONE}, which is the absence of a tracker
     *     and not one more to switch on — a caller holding it has nothing to ask the registry
     */
    public static Integration of(TicketProvider provider) {
        if (!provider.isEnabled()) {
            throw new IllegalArgumentException("No tracker is not an integration.");
        }
        return new Integration(IntegrationFamily.TRACKER, provider.wireName());
    }

    /** Every integration this version knows, by family in the order of {@link IntegrationFamily}, then by enum order. */
    public static List<Integration> all() {
        List<Integration> all = new ArrayList<>();
        Arrays.stream(ForgeKind.values()).map(Integration::of).forEach(all::add);
        Arrays.stream(SiemProtocol.values()).map(Integration::of).forEach(all::add);
        Arrays.stream(AiProvider.values()).map(Integration::of).forEach(all::add);
        Arrays.stream(NotificationChannelKind.values()).map(Integration::of).forEach(all::add);
        Arrays.stream(TicketProvider.values()).filter(TicketProvider::isEnabled).map(Integration::of).forEach(all::add);
        return List.copyOf(all);
    }

    /** The integration a key names, exactly — no trimming, no case folding: a key is an identifier, not prose. */
    public static Optional<Integration> byKey(String key) {
        return all().stream().filter(integration -> integration.key().equals(key)).findFirst();
    }
}

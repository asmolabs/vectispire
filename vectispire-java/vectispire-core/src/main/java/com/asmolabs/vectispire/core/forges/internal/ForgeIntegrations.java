package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.core.settings.Integrations;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * The forges' side of the integrations' registry (decision 0040 §1–2): which forge kinds this installation talks
 * to, asked by every place a forge connection is used.
 *
 * <p><b>Where it is asked, so that nothing goes round it.</b> At the three entries that hand a forge its token —
 * {@link ForgeProbes#probe} (a connection's creation, a new token, a new trust), the discovery's {@code
 * DiscoveryExecution} as it opens a run, and the change-review reading in {@code ForgeReviewService} before it
 * picks the forge's reader — and at the one gesture that calls no forge but acts on what it said, the import's
 * {@link ImportPlanner#plan}, which every preview and every import goes through. The routes' services ask it too,
 * first, so that a refusal comes before a form's other words ({@code ForgeConnectionService.create}, {@code
 * ForgeDiscoveryService.request}); they are not what makes it hold. The outbound guard is not where this is
 * decided: it judges addresses, and a disabled GitLab has a perfectly good one.
 *
 * <p><b>Nothing is written when a forge is switched off.</b> A connection of a disabled kind keeps its row, its
 * encrypted token, its snapshot and its readings; it reads {@code suspended} because this says so at every read,
 * and reads {@code active} again the moment a governor switches the forge back on.
 */
@Component
public class ForgeIntegrations {

    private final Integrations registry;

    public ForgeIntegrations(Integrations registry) {
        this.registry = registry;
    }

    public boolean enabled(ForgeKind kind) {
        return registry.isEnabled(Integration.of(kind));
    }

    /**
     * @throws IntegrationDisabledException 409 {@code integration-disabled}, naming {@code forge.<kind>}
     */
    public void requireEnabled(ForgeKind kind) {
        registry.requireEnabled(Integration.of(kind));
    }

    /** The forge kinds switched off, read once for a turn or a listing rather than once per connection. */
    public Set<ForgeKind> disabled() {
        Set<ForgeKind> disabled = EnumSet.noneOf(ForgeKind.class);
        Arrays.stream(ForgeKind.values()).filter(kind -> !enabled(kind)).forEach(disabled::add);
        return disabled;
    }

    /** The registry's keys of these kinds, for a log line: {@code forge.gitlab, forge.github}. */
    public static String keys(Set<ForgeKind> kinds) {
        return kinds.stream().map(kind -> Integration.of(kind).key()).collect(Collectors.joining(", "));
    }

    /** Why a line fed by a connection of this kind has no data, in the words its evidence carries. */
    public static String suspension(ForgeKind kind) {
        return "the " + Integration.of(kind).key() + " integration is disabled: the forge connection is suspended and "
                + "its change reviews are not read; a platform governor re-enables it in Administration, Integrations";
    }
}

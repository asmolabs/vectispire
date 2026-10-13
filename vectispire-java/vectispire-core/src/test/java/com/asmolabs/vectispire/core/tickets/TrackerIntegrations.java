package com.asmolabs.vectispire.core.tickets;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.core.settings.Integrations;

/**
 * The integrations' registry for a {@link TicketService} built by hand: every tracker enabled, as V92 seeds them, so
 * that a test about something else is not about the switch (decision 0040 §3). {@code TrackerSuspensionTest} switches.
 */
final class TrackerIntegrations {

    private TrackerIntegrations() {}

    static Integrations allEnabled() {
        Integrations registry = mock(Integrations.class);
        when(registry.isEnabled(any())).thenReturn(true);
        return registry;
    }
}

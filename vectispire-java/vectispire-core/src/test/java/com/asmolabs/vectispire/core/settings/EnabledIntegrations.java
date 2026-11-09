package com.asmolabs.vectispire.core.settings;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The integrations' registry for a service built by hand: every integration enabled, as V94 seeds them, so that a
 * test about something else is not about the switch (decision 0040). The switch itself is tested through the routes,
 * against the real registry.
 */
public final class EnabledIntegrations {

    private EnabledIntegrations() {}

    public static Integrations all() {
        Integrations registry = mock(Integrations.class);
        when(registry.isEnabled(any())).thenReturn(true);
        return registry;
    }
}

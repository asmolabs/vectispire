package com.asmolabs.vectispire.core.access;

import java.util.HashMap;
import java.util.Map;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

/**
 * {@link OidcProperties} as the application binds them, from the keys a test names — so a test states
 * what it changes and inherits the shipped defaults rather than restating them.
 */
public final class OidcSettings {

    private OidcSettings() {}

    /** @param pairs keys under {@code vectispire.oidc}, each followed by its value */
    public static OidcProperties bound(String... pairs) {
        Map<String, String> properties = new HashMap<>();
        for (int index = 0; index < pairs.length; index += 2) {
            properties.put("vectispire.oidc." + pairs[index], pairs[index + 1]);
        }
        return new Binder(new MapConfigurationPropertySource(properties))
                .bindOrCreate("vectispire.oidc", OidcProperties.class);
    }
}

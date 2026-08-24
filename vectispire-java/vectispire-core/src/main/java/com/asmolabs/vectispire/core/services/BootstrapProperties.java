package com.asmolabs.vectispire.core.services;

import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The credentials of the very first account.
 *
 * <p>Read once, on an empty users table, and ignored ever after — see {@code
 * BootstrapService} for why that condition is the whole safety of the mechanism.
 */
@ConfigurationProperties("vectispire.bootstrap")
public record BootstrapProperties(Optional<String> username, Optional<String> password) {

    public BootstrapProperties {
        username = username == null ? Optional.empty() : username.filter(value -> !value.isBlank());
        password = password == null ? Optional.empty() : password.filter(value -> !value.isBlank());
    }
}

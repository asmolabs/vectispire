package com.asmolabs.vectispire.core.access.web.scim;

import com.asmolabs.vectispire.core.crypto.SecretFile;
import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

/**
 * SCIM 2.0 configuration properties.
 */
@Validated
@ConfigurationProperties("vectispire.scim")
public record ScimProperties(
        boolean enabled,
        Optional<String> token,
        Optional<String> tokenFile) {

    /**
     * The shortest SCIM token accepted, in characters.
     *
     * <p>It is a static secret compared on every {@code /scim} request, held by a third system, and
     * the throttle on refused tokens is per address: its length is what makes guessing it pointless.
     * Thirty-two characters is what {@code openssl rand -base64 24} prints.
     */
    public static final int MIN_TOKEN_LENGTH = 32;

    @ConstructorBinding
    public ScimProperties {
        token = token == null ? Optional.empty() : token;
        tokenFile = tokenFile == null ? Optional.empty() : tokenFile.map(String::trim).filter(t -> !t.isEmpty());
        // **Refused at start, not at the first request**: an installation that would accept a short
        // token is one nobody hears about until the directory has been provisioning through it.
        if (enabled) {
            Optional<String> effective = tokenFile.isPresent()
                    ? Optional.of(SecretFile.read(tokenFile.get(), "VECTISPIRE_SCIM_TOKEN_FILE"))
                    : token;
            effective.filter(value -> value.length() < MIN_TOKEN_LENGTH).ifPresent(value -> {
                throw new IllegalStateException("The SCIM token is " + value.length() + " characters long; at least "
                        + MIN_TOKEN_LENGTH + " are required. Generate one with `openssl rand -base64 32`.");
            });
        }
    }

    public ScimProperties resolved() {
        if (tokenFile.isEmpty()) {
            return this;
        }
        Optional<String> resolvedToken = tokenFile
                .map(path -> SecretFile.read(path, "VECTISPIRE_SCIM_TOKEN_FILE"))
                .<String>map(s -> s)
                .or(() -> token);
        return new ScimProperties(enabled, resolvedToken, Optional.empty());
    }
}

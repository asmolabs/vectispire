package com.asmolabs.vectispire.core.api.scim;

import com.asmolabs.vectispire.core.services.SecretFile;
import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

/**
 * SCIM 2.0 configuration properties.
 */
@ConfigurationProperties("vectispire.scim")
public record ScimProperties(
        boolean enabled,
        Optional<String> token,
        Optional<String> tokenFile) {

    @ConstructorBinding
    public ScimProperties {
        token = token == null ? Optional.empty() : token;
        tokenFile = tokenFile == null ? Optional.empty() : tokenFile.map(String::trim).filter(t -> !t.isEmpty());
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

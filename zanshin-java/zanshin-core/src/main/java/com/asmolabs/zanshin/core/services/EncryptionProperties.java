package com.asmolabs.zanshin.core.services;

import java.util.List;
import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Where the encryption secrets come from.
 *
 * <p>Bound rather than read from {@code System.getenv} inside the service, for the reason
 * given in {@code CoreConfiguration}: a value a test cannot vary is a value nobody has ever
 * exercised the other branch of — and here the other branch is "no key configured", which is
 * exactly the state a fresh deployment starts in.
 *
 * @param key the current key. Everything is encrypted under it, and it is tried first when
 *     reading
 * @param previousKeys keys kept only for reading, so a rotation does not have to rewrite every
 *     row before the new key takes effect. Order is theirs; a key already listed as current is
 *     dropped rather than tried twice
 */
@ConfigurationProperties("zanshin.encryption")
public record EncryptionProperties(Optional<String> key, List<String> previousKeys) {

    public EncryptionProperties {
        key = key == null ? Optional.empty() : key;
        previousKeys = previousKeys == null
                ? List.of()
                : previousKeys.stream().map(String::trim).filter(secret -> !secret.isEmpty()).toList();
    }
}

package com.asmolabs.vectispire.core.services;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

/**
 * Where the encryption secrets and KMS settings come from.
 */
@ConfigurationProperties("vectispire.encryption")
public record EncryptionProperties(
        Optional<String> key,
        Optional<String> keyFile,
        List<String> previousKeys,
        Optional<String> previousKeysFile,
        Optional<String> kmsType,
        Optional<String> vaultEndpoint,
        Optional<String> vaultToken,
        Optional<String> vaultTokenFile,
        Optional<String> vaultKeyName,
        Optional<String> vaultMountPath) {

    @ConstructorBinding
    public EncryptionProperties {
        key = key == null ? Optional.empty() : key;
        keyFile = pathOrEmpty(keyFile);
        previousKeysFile = pathOrEmpty(previousKeysFile);
        previousKeys = previousKeys == null
                ? List.of()
                : previousKeys.stream().map(String::trim).filter(secret -> !secret.isEmpty()).toList();
        kmsType = pathOrEmpty(kmsType);
        vaultEndpoint = pathOrEmpty(vaultEndpoint);
        vaultToken = vaultToken == null ? Optional.empty() : vaultToken;
        vaultTokenFile = pathOrEmpty(vaultTokenFile);
        vaultKeyName = pathOrEmpty(vaultKeyName);
        vaultMountPath = pathOrEmpty(vaultMountPath);
    }

    public EncryptionProperties(Optional<String> key, List<String> previousKeys) {
        this(
                key,
                Optional.empty(),
                previousKeys,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty());
    }

    public EncryptionProperties(
            Optional<String> key,
            Optional<String> keyFile,
            List<String> previousKeys,
            Optional<String> previousKeysFile) {
        this(
                key,
                keyFile,
                previousKeys,
                previousKeysFile,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty());
    }

    public EncryptionProperties resolved() {
        if (keyFile.isEmpty() && previousKeysFile.isEmpty() && vaultTokenFile.isEmpty()) {
            return this;
        }

        refuseBoth(isSupplied(key), keyFile.isPresent(), "ENCRYPTION_KEY", "ENCRYPTION_KEY_FILE");
        refuseBoth(
                !previousKeys.isEmpty(),
                previousKeysFile.isPresent(),
                "VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS",
                "VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE");
        refuseBoth(
                isSupplied(vaultToken),
                vaultTokenFile.isPresent(),
                "VECTISPIRE_VAULT_TOKEN",
                "VECTISPIRE_VAULT_TOKEN_FILE");

        Optional<String> resolvedKey =
                keyFile.map(path -> SecretFile.read(path, "ENCRYPTION_KEY_FILE")).or(() -> key);
        List<String> resolvedPrevious = previousKeysFile
                .map(path -> SecretFile.read(path, "VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE"))
                .map(EncryptionProperties::splitKeys)
                .orElse(previousKeys);
        Optional<String> resolvedVaultToken = vaultTokenFile
                .map(path -> SecretFile.read(path, "VECTISPIRE_VAULT_TOKEN_FILE"))
                .or(() -> vaultToken);

        return new EncryptionProperties(
                resolvedKey,
                Optional.empty(),
                resolvedPrevious,
                Optional.empty(),
                kmsType,
                vaultEndpoint,
                resolvedVaultToken,
                Optional.empty(),
                vaultKeyName,
                vaultMountPath);
    }

    private static List<String> splitKeys(String content) {
        return Arrays.stream(content.split("[,\\r\\n]"))
                .map(String::trim)
                .filter(secret -> !secret.isEmpty())
                .toList();
    }

    private static boolean isSupplied(Optional<String> secret) {
        return secret.filter(value -> !value.isBlank()).isPresent();
    }

    private static void refuseBoth(boolean hasValue, boolean hasFile, String valueName, String fileName) {
        if (hasValue && hasFile) {
            throw new IllegalStateException(
                    valueName + " and " + fileName + " are both set. Nothing here can say which secret is "
                            + "in force without choosing one you did not, so it refuses rather than picking. "
                            + "Unset " + valueName + " once the file is in place.");
        }
    }

    private static Optional<String> pathOrEmpty(Optional<String> value) {
        return value == null ? Optional.empty() : value.map(String::trim).filter(text -> !text.isEmpty());
    }
}

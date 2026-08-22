package com.asmolabs.zanshin.common.domain.crypto;

import com.asmolabs.zanshin.common.domain.crypto.SecretCipher.Decrypted;
import java.util.List;
import java.util.Optional;

/**
 * Local AES-256-GCM encryption with scrypt key derivation and fallback decryption keys.
 */
public final class LocalKmsProvider implements KmsProvider {

    private final Optional<EncryptionKey> currentKey;
    private final List<EncryptionKey> decryptionKeys;
    private final SecretCipher cipher;

    public LocalKmsProvider(Optional<EncryptionKey> currentKey, List<EncryptionKey> decryptionKeys) {
        this(currentKey, decryptionKeys, new SecretCipher());
    }

    public LocalKmsProvider(
            Optional<EncryptionKey> currentKey, List<EncryptionKey> decryptionKeys, SecretCipher cipher) {
        this.currentKey = currentKey;
        this.decryptionKeys = List.copyOf(decryptionKeys);
        this.cipher = cipher;
    }

    @Override
    public boolean isConfigured() {
        return currentKey.isPresent();
    }

    @Override
    public String encrypt(String plainText, String context) {
        if (plainText == null || plainText.isEmpty()) {
            return plainText;
        }
        EncryptionKey key = currentKey.orElseThrow(() -> new IllegalStateException("No encryption key configured"));
        return cipher.encrypt(key, plainText, context);
    }

    @Override
    public Optional<String> decrypt(String encrypted, String context) {
        if (encrypted == null || encrypted.isEmpty()) {
            return Optional.empty();
        }
        for (EncryptionKey key : decryptionKeys) {
            Optional<String> decrypted = cipher.decrypt(key, encrypted, context);
            if (decrypted.isPresent()) {
                return decrypted;
            }
        }
        return Optional.empty();
    }

    @Override
    public Decrypted inspect(String encrypted, String context) {
        return cipher.decryptWithAny(decryptionKeys, encrypted, context);
    }
}

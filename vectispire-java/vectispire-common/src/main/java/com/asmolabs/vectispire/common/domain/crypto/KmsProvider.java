package com.asmolabs.vectispire.common.domain.crypto;

import com.asmolabs.vectispire.common.domain.crypto.SecretCipher.Decrypted;
import java.util.Optional;

/**
 * Strategy interface for key management and cryptographic operations.
 * Allows transparently alternating between local AES-GCM and external KMS (e.g. HashiCorp Vault Transit).
 */
public interface KmsProvider {

    /** Encrypts plain text bound to a specific context (associated authenticated data). */
    String encrypt(String plainText, String context);

    /** Decrypts a single ciphertext bound to a specific context. */
    Optional<String> decrypt(String encrypted, String context);

    /** Decrypts and reports the secret state (CURRENT, PREVIOUS_KEY, UNREADABLE). */
    Decrypted inspect(String encrypted, String context);

    /** Whether the KMS provider is configured and available to encrypt. */
    boolean isConfigured();
}

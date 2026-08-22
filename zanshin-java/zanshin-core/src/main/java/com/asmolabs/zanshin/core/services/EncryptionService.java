package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.crypto.EncryptionKey;
import com.asmolabs.zanshin.common.domain.crypto.SecretCipher;
import com.asmolabs.zanshin.common.domain.crypto.SecretCipher.Decrypted;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Encryption at rest, as the environment configures it.
 *
 * <p><b>Derivation happens here, once per key, at startup.</b> scrypt costs about a hundred
 * milliseconds: imperceptible when the application boots, ruinous if it were paid per
 * encrypted value. The derived keys are held for the service's lifetime.
 *
 * <p><b>The application ships no key towards its own secrets.</b> An earlier version
 * published one in this repository: anyone holding a copy of the database read every private
 * SSH key in it. Old values are not lost for that — an operator makes them readable again by
 * deliberately supplying the old key through {@code ZANSHIN_PREVIOUS_ENCRYPTION_KEYS}. The
 * difference is not cryptographic, it is about who decides.
 */
@Service
public class EncryptionService {

    private static final Logger log = LoggerFactory.getLogger(EncryptionService.class);

    /**
     * Absent when the deployment has no key configured.
     *
     * <p>The consequence is deliberately asymmetric: reading keeps working, writing does not.
     * An existing deployment must go on <em>reading</em> what it stored and its screens must go
     * on rendering, while refusing to write a secret it could not protect.
     */
    private final Optional<EncryptionKey> encryptionKey;

    private final List<EncryptionKey> decryptionKeys;
    private final SecretCipher cipher = new SecretCipher();

    public EncryptionService(EncryptionProperties configured) {
        // **Files are read here, and a failure stops the application.** This is the only place
        // that can refuse: `EncryptionService` tolerating a missing key is what makes a broken
        // secret mount look like a fresh installation, so the refusal has to happen before that
        // tolerance applies. See `SecretFile`.
        EncryptionProperties properties = configured.resolved();

        this.encryptionKey = properties.key().filter(secret -> !secret.isBlank()).map(EncryptionKey::derive);
        if (encryptionKey.isEmpty()) {
            log.warn(
                    "No encryption key configured — stored secrets stay readable, but no new one can be encrypted. "
                            + "Generate one with `openssl rand -base64 32`.");
        }

        // The current key first, so a value that has already been rotated never reports itself
        // as old. Duplicates are dropped rather than tried twice.
        List<EncryptionKey> keys = new ArrayList<>();
        encryptionKey.ifPresent(keys::add);
        for (String secret : properties.previousKeys()) {
            EncryptionKey derived = EncryptionKey.derive(secret);
            if (!keys.contains(derived)) {
                keys.add(derived);
            }
        }
        this.decryptionKeys = List.copyOf(keys);
    }

    /** Lets a screen report the misconfiguration <em>before</em> asking for a secret. */
    public boolean isConfigured() {
        return encryptionKey.isPresent();
    }

    public String encrypt(String plainText, String context) {
        if (plainText == null || plainText.isEmpty()) {
            return plainText;
        }
        return cipher.encrypt(encryptionKey.orElseThrow(MissingEncryptionKeyException::new), plainText, context);
    }

    /**
     * The plaintext <b>and its state</b>.
     *
     * <p>The state is returned rather than logged: a secret readable only under a previous key
     * has not finished being rotated, and that is something an operator needs on a screen, not
     * in a file they are not watching.
     */
    public Decrypted inspect(String encrypted, String context) {
        return cipher.decryptWithAny(decryptionKeys, encrypted, context);
    }
}

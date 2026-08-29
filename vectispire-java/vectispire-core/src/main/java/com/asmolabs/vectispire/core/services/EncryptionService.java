package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.crypto.EncryptionKey;
import com.asmolabs.vectispire.common.domain.crypto.KmsProvider;
import com.asmolabs.vectispire.common.domain.crypto.LocalKmsProvider;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher.Decrypted;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.core.services.crypto.VaultKmsProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Encryption at rest, as the environment or KMS configures it.
 *
 * <p>Supports local AES-256-GCM derivation (scrypt) and external KMS providers (HashiCorp Vault Transit).
 */
@Service
public class EncryptionService {

    private static final Logger log = LoggerFactory.getLogger(EncryptionService.class);

    private final KmsProvider kms;

    public EncryptionService(EncryptionProperties configured) {
        this(configured, Optional.empty(), Optional.empty(), Optional.empty());
    }

    @Autowired
    public EncryptionService(
            EncryptionProperties configured,
            Optional<PinnedHttpSender> http,
            Optional<OutboundUrlGuard> guard,
            Optional<ObjectMapper> json) {

        EncryptionProperties properties = configured.resolved();

        Optional<EncryptionKey> primaryKey =
                properties.key().filter(secret -> !secret.isBlank()).map(EncryptionKey::derive);
        List<EncryptionKey> keys = new ArrayList<>();
        primaryKey.ifPresent(keys::add);
        for (String secret : properties.previousKeys()) {
            EncryptionKey derived = EncryptionKey.derive(secret);
            if (!keys.contains(derived)) {
                keys.add(derived);
            }
        }
        List<EncryptionKey> decryptionKeys = List.copyOf(keys);

        LocalKmsProvider local = new LocalKmsProvider(primaryKey, decryptionKeys);

        String kmsType = properties.kmsType().orElse("local").toLowerCase();
        if ("vault".equals(kmsType) && properties.vaultEndpoint().isPresent() && properties.vaultToken().isPresent()) {
            log.info("Configuring HashiCorp Vault Transit KMS at {}", properties.vaultEndpoint().get());
            PinnedHttpSender sender = http.orElseGet(PinnedHttpSender::new);
            OutboundUrlGuard urlGuard = guard.orElseGet(OutboundUrlGuard::new);
            ObjectMapper mapper = json.orElseGet(ObjectMapper::new);

            this.kms = new VaultKmsProvider(
                    properties.vaultEndpoint().get(),
                    properties.vaultToken().get(),
                    properties.vaultKeyName().orElse("vectispire"),
                    properties.vaultMountPath().orElse("transit"),
                    sender,
                    urlGuard,
                    mapper,
                    local);
        } else {
            if ("vault".equals(kmsType)) {
                // **Asking for Vault and silently not getting it is the failure this refuses.**
                // The fallback logged a warning and carried on with a local scrypt-derived key,
                // so an expired token at boot moved every subsequent write out of Transit's
                // custody — a change of who holds the keys, announced on a line nobody reads.
                // Worse, the two are not interchangeable afterwards: secrets written under the
                // local key are not in Vault, and a later boot that *does* reach Transit cannot
                // read them.
                //
                // `kmsType` is not a default — somebody set it to `vault` on purpose. Refusing
                // to start is the only answer that keeps that decision meaning something, and
                // an instance that will not start is a page at 03:00 rather than a discovery
                // during an audit.
                throw new IllegalStateException(
                        "Vault KMS is configured (vectispire.encryption.kms-type=vault) but "
                                + (properties.vaultEndpoint().isEmpty()
                                        ? "no endpoint was provided"
                                        : "no token was provided")
                                + ". Refusing to start rather than falling back to local "
                                + "encryption: secrets written under a local key are not in "
                                + "Vault and a later boot that reaches Transit cannot read "
                                + "them. Set vectispire.encryption.vault-endpoint and "
                                + "vault-token, or set kms-type=local deliberately.");
            }
            if (primaryKey.isEmpty()) {
                log.warn(
                        "No encryption key configured — stored secrets stay readable, but no new one can be encrypted. "
                                + "Generate one with `openssl rand -base64 32`.");
            }
            this.kms = local;
        }
    }

    /** Lets a screen report the misconfiguration <em>before</em> asking for a secret. */
    public boolean isConfigured() {
        return kms.isConfigured();
    }

    /**
     * Whether key custody is external.
     *
     * <p>Reported to the compliance engine rather than asserted by it: "encrypted" and "encrypted
     * with a key held on the same host as the ciphertext" are not the same claim, and an assessor
     * asks which one it is. No control requires Vault today, so this narrows a statement rather
     * than gating one.
     */
    public boolean isExternallyManaged() {
        return kms instanceof VaultKmsProvider;
    }

    public String encrypt(String plainText, String context) {
        if (plainText == null || plainText.isEmpty()) {
            return plainText;
        }
        if (!kms.isConfigured()) {
            throw new MissingEncryptionKeyException();
        }
        return kms.encrypt(plainText, context);
    }

    public Decrypted inspect(String encrypted, String context) {
        return kms.inspect(encrypted, context);
    }

    /**
     * Reads a stored credential, tolerating one written before it was encrypted.
     *
     * <p><b>Why the tolerance exists, and why it is not silent.</b> The generic settings route used
     * to accept these values and store them verbatim. Deployments therefore hold rows that carry a
     * working credential with no {@code v2:} prefix, and {@link SecretCipher} answers UNREADABLE to
     * anything it did not write — so decrypting strictly would not protect those rows, it would
     * disable the integration that depends on them, on upgrade, without a message. A tracker would
     * simply stop being reached; a webhook route would start refusing its own tracker.
     *
     * <p>So a legacy value is used and <b>reported at warn on every read</b>, naming the setting
     * and what to do. Re-saving through the owning route encrypts it and the warning stops. It is
     * not re-encrypted here on the operator's behalf: a read that writes is a surprise inside every
     * caller, and the row is already in the clear — reading it changes nothing about that.
     *
     * @return the credential, or empty when none is stored or none can be read
     */
    public String readSecret(String stored, String context, String label) {
        String value = stored == null ? "" : stored.trim();
        if (value.isEmpty()) {
            return "";
        }
        if (!value.startsWith(SecretCipher.FORMAT_PREFIX)) {
            log.warn("{} is stored in the clear — it predates encryption, or was written through a route that did "
                    + "not encrypt it. It still works. Save it again from the settings screen to encrypt it.", label);
            return value;
        }
        Decrypted secret = inspect(value, context);
        if (secret.state() == SecretCipher.SecretState.UNREADABLE) {
            log.error("{} cannot be decrypted by any configured key — the feature that uses it is disabled until "
                    + "it is set again.", label);
            return "";
        }
        return secret.plainText();
    }
}

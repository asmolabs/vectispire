package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.crypto.EncryptionKey;
import com.asmolabs.zanshin.common.domain.crypto.KmsProvider;
import com.asmolabs.zanshin.common.domain.crypto.LocalKmsProvider;
import com.asmolabs.zanshin.common.domain.crypto.SecretCipher.Decrypted;
import com.asmolabs.zanshin.common.domain.net.OutboundUrlGuard;
import com.asmolabs.zanshin.core.services.crypto.VaultKmsProvider;
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
                    properties.vaultKeyName().orElse("zanshin"),
                    properties.vaultMountPath().orElse("transit"),
                    sender,
                    urlGuard,
                    mapper,
                    local);
        } else {
            if ("vault".equals(kmsType)) {
                log.warn("Vault KMS requested but missing endpoint or token. Falling back to local encryption.");
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
}

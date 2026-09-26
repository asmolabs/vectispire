package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

/** The deployment keys: stored encrypted, and the private half never read back out. */
@Service
public class SshKeyAdministrationService {

    /**
     * A private key has one header worth recognising, and nothing else.
     *
     * <p>The rest never leaves the database: there is no screen where displaying it would help,
     * and many where it would be a leak.
     */
    private static final Pattern PRIVATE_KEY_HEADER = Pattern.compile("^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----");

    private static final int NAME_LENGTH = 255;

    /** Encrypted, this still fits MySQL's 65,535-byte {@code text}: see {@link #add}. */
    private static final int MAX_KEY_LENGTH = BoundedText.TEXT_MAX;

    private final SshKeyRepository keys;
    private final GitRepositoryRepository repositories;
    private final EncryptionService encryption;
    private final AuditLogService audit;
    private final Clock clock;

    public SshKeyAdministrationService(
            SshKeyRepository keys,
            GitRepositoryRepository repositories,
            EncryptionService encryption,
            AuditLogService audit,
            Clock clock) {
        this.keys = keys;
        this.repositories = repositories;
        this.encryption = encryption;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * @param encryptionState deserves a column and not a log line: a key readable only under a
     *     previous encryption key has not finished being rotated, and one that <em>no</em>
     *     configured key reads will fail the next clone that needs it — at scan time, in a
     *     worker thread, hours later
     */
    public record KeyView(
            UUID id,
            String name,
            String publicKey,
            Instant createdAt,
            String encryptionState,
            long usedByRepositories) {}

    public List<KeyView> list() {
        Map<UUID, Long> usage = usageByKey();
        return keys.findAllByOrderByCreatedAtDesc().stream()
                .map(key -> new KeyView(
                        key.getId(),
                        key.getName(),
                        key.getPublicKey(),
                        key.getCreatedAt(),
                        encryption
                                .inspect(key.getPrivateKey(), SecretCipher.privateKeyContext(key.getId().toString()))
                                .state()
                                .name()
                                .toLowerCase(Locale.ROOT),
                        usage.getOrDefault(key.getId(), 0L)))
                .toList();
    }

    public KeyView add(String rawName, String rawPrivateKey, String rawPublicKey, RequestActor actor) {
        String name = trim(rawName);
        String privateKey = trim(rawPrivateKey);
        String publicKey = trim(rawPublicKey);

        if (name.isEmpty()) {
            throw new IllegalArgumentException("A name is required.");
        }
        if (privateKey.isEmpty()) {
            throw new IllegalArgumentException("The private key is required.");
        }
        // The name goes into a varchar(255), the keys into `text` — the private one encrypted, a
        // third longer. An RSA key of 16,384 bits is under 13,000 characters in PEM; the ceiling
        // keeps any key that exists and refuses the paste of a whole file tree, which the database
        // used to refuse instead, as a 500.
        BoundedText.within(name, NAME_LENGTH, "The name");
        BoundedText.within(privateKey, MAX_KEY_LENGTH, "The private key");
        BoundedText.within(publicKey, MAX_KEY_LENGTH, "The public key");
        if (!PRIVATE_KEY_HEADER.matcher(privateKey).find()) {
            // Refused on entry: otherwise the error only shows at the first clone, in an agent's
            // log, and looks like a network problem.
            throw new IllegalArgumentException(
                    "This does not look like a private key: expected a \"-----BEGIN … PRIVATE KEY-----\" block.");
        }

        UUID id = UUID.randomUUID();
        SshKeyEntity key = new SshKeyEntity();
        key.setId(id);
        key.setName(name);
        // The context binds the ciphertext to *this* row: copied elsewhere it becomes unreadable
        // rather than decrypting the wrong key.
        key.setPrivateKey(encryption.encrypt(privateKey, SecretCipher.privateKeyContext(id.toString())));
        key.setPublicKey(publicKey.isEmpty() ? null : publicKey);
        key.setCreatedAt(clock.instant());

        SshKeyEntity saved = keys.save(key);
        record(actor, id.toString(), "SSH key added: " + name);
        return new KeyView(
                saved.getId(),
                saved.getName(),
                saved.getPublicKey(),
                saved.getCreatedAt(),
                SecretCipher.SecretState.CURRENT.name().toLowerCase(Locale.ROOT),
                0);
    }

    public void remove(UUID id, RequestActor actor) {
        SshKeyEntity key = keys.findById(id).orElseThrow(() -> new NoSuchElementException("Key not found."));

        long inUse = repositories.countBySshKeyId(id);
        if (inUse > 0) {
            // Deleting the key would break the next scan of those repositories, and the failure
            // would land far from here. The refusal says how many to detach first.
            throw new IllegalArgumentException(
                    "This key is used by " + inUse + " repository(ies). Detach it from them first.");
        }

        keys.deleteById(id);
        record(actor, id.toString(), "SSH key deleted: " + key.getName());
    }

    private Map<UUID, Long> usageByKey() {
        Map<UUID, Long> usage = new HashMap<>();
        for (Object[] row : repositories.countBySshKey()) {
            usage.put((UUID) row[0], ((Number) row[1]).longValue());
        }
        return usage;
    }

    private void record(RequestActor actor, String resourceId, String description) {
        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                resourceId,
                description,
                actor.username(),
                actor.ipAddress(),
                actor.userAgent()));
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }
}

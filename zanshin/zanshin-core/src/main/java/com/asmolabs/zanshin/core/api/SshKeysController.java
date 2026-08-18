package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.crypto.SecretCipher;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.SshKeyEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.SshKeys;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.EncryptionService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** The deployment keys. Administrators only, and the private half never leaves. */
@RestController
@RequestMapping("/api/v1/ssh-keys")
@PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN')")
public class SshKeysController {

    /**
     * A private key has one header worth showing, and nothing else.
     *
     * <p>The rest never leaves the database: there is no screen where displaying it would help,
     * and many where it would be a leak.
     */
    private static final Pattern PRIVATE_KEY_HEADER = Pattern.compile("^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----");

    private final SshKeys keys;
    private final GitRepositories repositories;
    private final EncryptionService encryption;
    private final AuditLogService audit;
    private final Clock clock;

    public SshKeysController(
            SshKeys keys,
            GitRepositories repositories,
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
    public record Summary(
            UUID id,
            String name,
            String publicKey,
            Instant createdAt,
            String encryptionState,
            long usedByRepositories) {}

    public record CreateRequest(String name, String privateKey, String publicKey) {}

    @GetMapping
    public List<Summary> list() {
        Map<UUID, Long> usage = usageByKey();
        return keys.findAllByOrderByCreatedAtDesc().stream()
                .map(key -> new Summary(
                        key.getId(),
                        key.getName(),
                        key.getPublicKey(),
                        key.getCreatedAt(),
                        encryption
                                .inspect(key.getPrivateKey(), SecretCipher.privateKeyContext(key.getId().toString()))
                                .state()
                                .name()
                                .toLowerCase(java.util.Locale.ROOT),
                        usage.getOrDefault(key.getId(), 0L)))
                .toList();
    }

    @PostMapping
    public Summary create(
            @RequestBody CreateRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        String name = trim(body.name());
        String privateKey = trim(body.privateKey());
        String publicKey = trim(body.publicKey());

        if (name.isEmpty()) {
            throw new IllegalArgumentException("A name is required.");
        }
        if (privateKey.isEmpty()) {
            throw new IllegalArgumentException("The private key is required.");
        }
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
        record(principal, request, id.toString(), "SSH key added: " + name);
        return new Summary(
                saved.getId(),
                saved.getName(),
                saved.getPublicKey(),
                saved.getCreatedAt(),
                SecretCipher.SecretState.CURRENT.name().toLowerCase(java.util.Locale.ROOT),
                0);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable UUID id,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        SshKeyEntity key = keys.findById(id).orElseThrow(() -> new NoSuchElementException("Key not found."));

        long inUse = repositories.countBySshKeyId(id);
        if (inUse > 0) {
            // Deleting the key would break the next scan of those repositories, and the failure
            // would land far from here. The refusal says how many to detach first.
            throw new IllegalArgumentException(
                    "This key is used by " + inUse + " repository(ies). Detach it from them first.");
        }

        keys.deleteById(id);
        record(principal, request, id.toString(), "SSH key deleted: " + key.getName());
    }

    private Map<UUID, Long> usageByKey() {
        Map<UUID, Long> usage = new HashMap<>();
        for (Object[] row : repositories.countBySshKey()) {
            usage.put((UUID) row[0], ((Number) row[1]).longValue());
        }
        return usage;
    }

    private void record(
            ZanshinPrincipal principal, HttpServletRequest request, String resourceId, String description) {
        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                resourceId,
                description,
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }
}

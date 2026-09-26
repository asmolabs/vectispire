package com.asmolabs.vectispire.core.services.targets;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.persistence.GitTokenEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.GitTokens;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * HTTPS clone tokens: stored encrypted, bound to a host, never read back out (decision 0022).
 *
 * <p>The counterpart of {@link SshKeyAdministrationService}, and deliberately shaped like it — an
 * operator who knows one screen knows the other, and the two refuse the same things for the same
 * reasons.
 */
@Service
public class GitTokenAdministrationService {

    private static final int NAME_LENGTH = 255;

    /** Encrypted, this still fits MySQL's 65,535-byte {@code text}: see {@link #add}. */
    private static final int MAX_TOKEN_LENGTH = 8_192;

    private final GitTokens tokens;
    private final GitRepositories repositories;
    private final EncryptionService encryption;
    private final AuditLogService audit;
    private final Clock clock;

    public GitTokenAdministrationService(
            GitTokens tokens,
            GitRepositories repositories,
            EncryptionService encryption,
            AuditLogService audit,
            Clock clock) {
        this.tokens = tokens;
        this.repositories = repositories;
        this.encryption = encryption;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * @param encryptionState as for SSH keys: a token no configured key reads fails the next clone
     *     that needs it, hours later in a worker thread, so the screen says it first
     */
    public record TokenView(
            UUID id,
            String name,
            String host,
            String username,
            Instant createdAt,
            String encryptionState,
            long usedByRepositories) {}

    public List<TokenView> list() {
        Map<UUID, Long> usage = new HashMap<>();
        for (Object[] row : repositories.countByHttpsToken()) {
            usage.put((UUID) row[0], ((Number) row[1]).longValue());
        }
        return tokens.findAllByOrderByCreatedAtDesc().stream()
                .map(token -> new TokenView(
                        token.getId(),
                        token.getName(),
                        token.getHost(),
                        token.getUsername(),
                        token.getCreatedAt(),
                        encryption
                                .inspect(token.getToken(), SecretCipher.gitTokenContext(token.getId().toString()))
                                .state()
                                .name()
                                .toLowerCase(Locale.ROOT),
                        usage.getOrDefault(token.getId(), 0L)))
                .toList();
    }

    /**
     * @param rawHost the only host the token will ever be presented to — see decision 0022 for what
     *     an unbound token would let a repository URL do with it
     */
    public TokenView add(String rawName, String rawHost, String rawUsername, String rawToken, RequestActor actor) {
        String name = trim(rawName);
        String token = trim(rawToken);
        String username = trim(rawUsername);
        if (name.isEmpty()) {
            throw new IllegalArgumentException("A name is required.");
        }
        if (token.isEmpty()) {
            throw new IllegalArgumentException("The token is required.");
        }
        // The name and the username go into varchar(255) columns, and past them the database
        // refused the row at the write, as a 500. The token goes into `text` encrypted: a third
        // longer, and bounded so that the ciphertext always fits MySQL's 64 KB. No forge issues a
        // token within two orders of magnitude of the ceiling.
        BoundedText.within(name, NAME_LENGTH, "The name");
        BoundedText.within(username, NAME_LENGTH, "The username");
        BoundedText.within(token, MAX_TOKEN_LENGTH, "The token");
        if (token.chars().anyMatch(Character::isWhitespace)) {
            // A pasted line break or a "Bearer " prefix: the forge would refuse it at the first clone,
            // far from here, as an authentication failure.
            throw new IllegalArgumentException("The token contains spaces or line breaks: paste the token alone.");
        }
        String host = RepositoryUrl.normalizeHost(rawHost);

        UUID id = UUID.randomUUID();
        GitTokenEntity entity = new GitTokenEntity();
        entity.setId(id);
        entity.setName(name);
        entity.setHost(host);
        entity.setUsername(username.isEmpty() ? null : username);
        entity.setToken(encryption.encrypt(token, SecretCipher.gitTokenContext(id.toString())));
        entity.setCreatedAt(clock.instant());

        GitTokenEntity saved = tokens.save(entity);
        record(actor, id.toString(), "HTTPS token added: " + name + " (" + host + ")");
        return new TokenView(
                saved.getId(),
                saved.getName(),
                saved.getHost(),
                saved.getUsername(),
                saved.getCreatedAt(),
                SecretCipher.SecretState.CURRENT.name().toLowerCase(Locale.ROOT),
                0);
    }

    public void remove(UUID id, RequestActor actor) {
        GitTokenEntity token = tokens.findById(id).orElseThrow(() -> new NoSuchElementException("Token not found."));
        long inUse = repositories.countByHttpsTokenId(id);
        if (inUse > 0) {
            throw new IllegalArgumentException(
                    "This token is used by " + inUse + " repository(ies). Detach it from them first.");
        }
        tokens.deleteById(id);
        record(actor, id.toString(), "HTTPS token deleted: " + token.getName());
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

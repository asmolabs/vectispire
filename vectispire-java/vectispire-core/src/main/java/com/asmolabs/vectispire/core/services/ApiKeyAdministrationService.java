package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeys;
import com.asmolabs.vectispire.common.domain.apikeys.InvalidApiKeyException;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.core.persistence.ApiKeyEntity;
import com.asmolabs.vectispire.core.repositories.ApiKeysRepository;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import java.time.Clock;
import java.time.Instant;
import java.time.Period;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;

/** Issuing, listing and revoking API keys. */
@Service
public class ApiKeyAdministrationService {

    private final ApiKeysRepository keys;
    private final GitRepositories repositories;
    private final Containers containers;
    private final TargetNaming naming;
    private final AuditLogService audit;
    private final Clock clock;

    public ApiKeyAdministrationService(
            ApiKeysRepository keys,
            GitRepositories repositories,
            Containers containers,
            TargetNaming naming,
            AuditLogService audit,
            Clock clock) {
        this.keys = keys;
        this.repositories = repositories;
        this.containers = containers;
        this.naming = naming;
        this.audit = audit;
        this.clock = clock;
    }

    /** Who asked, as the audit log records it. */
    public record Actor(String username, String ipAddress, String userAgent) {}

    /**
     * A key as it may be shown: never its hash.
     *
     * @param expired computed here and not on the screen: an expired key is refused by the
     *     server, and two notions of "expired" would eventually disagree by a timezone
     */
    public record KeyView(
            UUID id,
            String name,
            String prefix,
            List<String> scopes,
            String targetKind,
            Long targetId,
            String targetLabel,
            Instant createdAt,
            Instant lastUsedAt,
            Instant expiresAt,
            boolean expired) {}

    public record Request(String name, List<String> scopes, String targetKind, Long targetId, Integer expiresInDays) {}

    /** @param secret the only occurrence of the plaintext */
    public record Issued(KeyView key, String secret) {}

    public record TargetOption(Long id, String label) {}

    public record TargetOptions(List<TargetOption> repositories, List<TargetOption> containers) {}

    public List<KeyView> list() {
        Instant asOf = clock.instant();
        TargetNaming.Names names = naming.all();
        return keys.findAllByOrderByCreatedAtDesc().stream()
                .map(key -> viewOf(key, asOf, names))
                .toList();
    }

    /**
     * Issues a key and <b>returns it once</b>.
     *
     * <p>This is the only place the plaintext exists. An earlier implementation permanently
     * displayed the row's identifier as though it were the secret — so there had never been a
     * secret. Making it unrecoverable is the point.
     */
    public Issued issue(Request request, Actor actor) {
        String name = request.name() == null ? "" : request.name().trim();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("A name is required.");
        }

        List<ApiKeyScope> scopes = ApiKeys.normalizeScopes(request.scopes());
        Optional<Period> lifetime = ApiKeys.normalizeLifetime(request.expiresInDays());
        String targetKind = normalizeTargetKind(request);
        if (targetKind != null) {
            assertTargetExists(targetKind, request.targetId());
        }

        ApiKeys.IssuedKey issued = ApiKeys.generate();
        Instant issuedAt = clock.instant();

        ApiKeyEntity key = new ApiKeyEntity();
        key.setName(name);
        key.setKeyHash(PasswordHasher.hash(issued.fullKey()));
        key.setPrefix(issued.prefix());
        key.setScopes(String.join(",", scopes.stream().map(ApiKeyScope::wireName).toList()));
        key.setTargetKind(targetKind);
        key.setTargetId(targetKind == null ? null : request.targetId());
        key.setCreatedAt(issuedAt);
        key.setExpiresAt(lifetime.map(issuedAt::plus).orElse(null));

        ApiKeyEntity saved = keys.save(key);
        record(actor, AuditOperation.API_KEY_CREATED, saved.getId().toString(),
                "API key issued: " + name + " (" + saved.getScopes() + ")");

        return new Issued(viewOf(saved, issuedAt, naming.all()), issued.fullKey());
    }

    public void revoke(UUID id, Actor actor) {
        ApiKeyEntity key = keys.findById(id).orElseThrow(() -> new NoSuchElementException("Key not found."));

        // Revoking deletes the row: a "disabled" key that a scan could re-enable by accident
        // would be worse than an absent one. The audit trail keeps the record.
        keys.deleteById(id);
        record(actor, AuditOperation.API_KEY_DELETED, id.toString(), "API key revoked: " + key.getName());
    }

    /** The targets a key can be restricted to, so the screen offers names rather than numbers. */
    public TargetOptions targets() {
        List<TargetOption> repositoryOptions = new ArrayList<>();
        repositories.findAll()
                .forEach(repository -> repositoryOptions.add(
                        new TargetOption(repository.getId(), TargetNaming.of(repository))));

        List<TargetOption> containerOptions = new ArrayList<>();
        containers.findAll()
                .forEach(container -> containerOptions.add(
                        new TargetOption(container.getId(), TargetNaming.of(container))));

        return new TargetOptions(repositoryOptions, containerOptions);
    }

    private void assertTargetExists(String kind, Long id) {
        boolean exists = "repository".equals(kind)
                ? repositories.existsById(id)
                : containers.existsById(id);
        if (!exists) {
            // A key restricted to a target that does not exist can do nothing, and finding that
            // out would happen on the pipeline's first call.
            throw new InvalidApiKeyException("No \"" + kind + "\" target with id " + id + ".");
        }
    }

    /** Empty for an unrestricted key; refused when the kind and the identifier disagree. */
    private static String normalizeTargetKind(Request request) {
        String kind = request.targetKind() == null ? "" : request.targetKind().trim().toLowerCase(Locale.ROOT);
        if (kind.isEmpty() && request.targetId() == null) {
            return null;
        }
        if (kind.isEmpty() || request.targetId() == null) {
            throw new InvalidApiKeyException("A restricted key needs both a target kind and a target id.");
        }
        if (!"repository".equals(kind) && !"container".equals(kind)) {
            throw new InvalidApiKeyException("Unknown target kind: \"" + kind + "\".");
        }
        return kind;
    }

    private static KeyView viewOf(ApiKeyEntity key, Instant asOf, TargetNaming.Names names) {
        return new KeyView(
                key.getId(),
                key.getName(),
                key.getPrefix(),
                key.getScopes() == null || key.getScopes().isEmpty()
                        ? List.of()
                        : List.of(key.getScopes().split(",")),
                key.getTargetKind(),
                key.getTargetId(),
                targetLabel(key, names),
                key.getCreatedAt(),
                key.getLastUsedAt(),
                key.getExpiresAt(),
                key.getExpiresAt() != null && !key.getExpiresAt().isAfter(asOf));
    }

    /** A target deleted since the key was issued: say so rather than showing a blank. */
    private static String targetLabel(ApiKeyEntity key, TargetNaming.Names names) {
        if (key.getTargetKind() == null || key.getTargetId() == null) {
            return null;
        }
        return "repository".equals(key.getTargetKind())
                ? names.repositories().getOrDefault(key.getTargetId(), key.getTargetKind() + " " + key.getTargetId() + " (deleted)")
                : names.containers().getOrDefault(key.getTargetId(), key.getTargetKind() + " " + key.getTargetId() + " (deleted)");
    }

    private void record(Actor actor, AuditOperation operation, String resourceId, String description) {
        audit.record(new AuditLogService.Record(
                operation, resourceId, description, actor.username(), actor.ipAddress(), actor.userAgent()));
    }
}

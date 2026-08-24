package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeys;
import com.asmolabs.vectispire.common.domain.apikeys.InvalidApiKeyException;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.ApiKeyEntity;
import com.asmolabs.vectispire.core.repositories.ApiKeysRepository;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.TargetNaming;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import java.time.Period;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** The API keys. Administrators only. */
@RestController
@RequestMapping("/api/v1/api-keys")
@RequiresAdministrator
public class ApiKeysController {

    private final ApiKeysRepository keys;
    private final GitRepositories repositories;
    private final Containers containers;
    private final TargetNaming naming;
    private final AuditLogService audit;
    private final Clock clock;

    public ApiKeysController(
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

    /**
     * What a key shows.
     *
     * <p>{@code keyHash} is not on it; {@code prefix} is, and it is not a secret.
     *
     * @param isExpired computed here and not on the screen: an expired key is refused by the
     *     server, and two notions of "expired" would eventually disagree by a timezone
     */
    public record Summary(
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
            boolean isExpired) {}

    public record CreateRequest(
            String name,
            List<String> scopes,
            @JsonProperty("target_kind") String targetKind,
            @JsonProperty("target_id") Long targetId,
            @JsonProperty("expires_in_days") Integer expiresInDays) {}

    /** @param secret the only occurrence of the plaintext. It will never appear again */
    public record IssuedKey(Summary key, String secret) {}

    public record TargetOption(Long id, String label) {}

    public record Targets(List<TargetOption> repositories, List<TargetOption> containers) {}

    @GetMapping
    public List<Summary> list() {
        Instant asOf = clock.instant();
        TargetNaming.Names names = naming.all();
        return keys.findAllByOrderByCreatedAtDesc().stream()
                .map(key -> summaryOf(key, asOf, names))
                .toList();
    }

    /**
     * Issues a key and <b>returns it once</b>.
     *
     * <p>This is the only place the plaintext exists. An earlier implementation permanently
     * displayed the row's identifier as though it were the secret — so there had never been a
     * secret. Making it unrecoverable is the point.
     */
    @PostMapping
    public IssuedKey create(
            @RequestBody CreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String name = body.name() == null ? "" : body.name().trim();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("A name is required.");
        }

        List<ApiKeyScope> scopes = ApiKeys.normalizeScopes(body.scopes());
        Optional<Period> lifetime = ApiKeys.normalizeLifetime(body.expiresInDays());
        String targetKind = normalizeTargetKind(body);
        if (targetKind != null) {
            assertTargetExists(targetKind, body.targetId());
        }

        ApiKeys.IssuedKey issued = ApiKeys.generate();
        Instant issuedAt = clock.instant();

        ApiKeyEntity key = new ApiKeyEntity();
        key.setName(name);
        key.setKeyHash(PasswordHasher.hash(issued.fullKey()));
        key.setPrefix(issued.prefix());
        key.setScopes(String.join(",", scopes.stream().map(ApiKeyScope::wireName).toList()));
        key.setTargetKind(targetKind);
        key.setTargetId(targetKind == null ? null : body.targetId());
        key.setCreatedAt(issuedAt);
        key.setExpiresAt(lifetime.map(issuedAt::plus).orElse(null));

        ApiKeyEntity saved = keys.save(key);
        record(principal, request, AuditOperation.API_KEY_CREATED, saved.getId().toString(),
                "API key issued: " + name + " (" + saved.getScopes() + ")");

        return new IssuedKey(summaryOf(saved, issuedAt, naming.all()), issued.fullKey());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable UUID id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        ApiKeyEntity key = keys.findById(id).orElseThrow(() -> new NoSuchElementException("Key not found."));

        // Revoking deletes the row: a "disabled" key that a scan could re-enable by accident
        // would be worse than an absent one. The audit trail keeps the record.
        keys.deleteById(id);
        record(principal, request, AuditOperation.API_KEY_DELETED, id.toString(),
                "API key revoked: " + key.getName());
    }

    /** The targets a key can be restricted to, so the screen offers names rather than numbers. */
    @GetMapping("/targets")
    public Targets targets() {
        List<TargetOption> repositoryOptions = new ArrayList<>();
        repositories.findAll()
                .forEach(repository -> repositoryOptions.add(
                        new TargetOption(repository.getId(), TargetNaming.of(repository))));

        List<TargetOption> containerOptions = new ArrayList<>();
        containers.findAll()
                .forEach(container -> containerOptions.add(
                        new TargetOption(container.getId(), TargetNaming.of(container))));

        return new Targets(repositoryOptions, containerOptions);
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
    private static String normalizeTargetKind(CreateRequest body) {
        String kind = body.targetKind() == null ? "" : body.targetKind().trim().toLowerCase(java.util.Locale.ROOT);
        if (kind.isEmpty() && body.targetId() == null) {
            return null;
        }
        if (kind.isEmpty() || body.targetId() == null) {
            throw new InvalidApiKeyException("A restricted key needs both a target kind and a target id.");
        }
        if (!"repository".equals(kind) && !"container".equals(kind)) {
            throw new InvalidApiKeyException("Unknown target kind: \"" + kind + "\".");
        }
        return kind;
    }

    private Summary summaryOf(ApiKeyEntity key, Instant asOf, TargetNaming.Names names) {
        return new Summary(
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

    private void record(
            VectispirePrincipal principal,
            HttpServletRequest request,
            AuditOperation operation,
            String resourceId,
            String description) {
        audit.record(new AuditLogService.Record(
                operation,
                resourceId,
                description,
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));
    }
}

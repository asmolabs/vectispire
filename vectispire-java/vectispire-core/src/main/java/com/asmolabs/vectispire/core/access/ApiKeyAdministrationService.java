package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.common.domain.users.AccountRules;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeys;
import com.asmolabs.vectispire.common.domain.apikeys.InvalidApiKeyException;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.persistence.ApiKeyEntity;
import com.asmolabs.vectispire.core.access.persistence.ApiKeyRepository;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import java.time.Clock;
import java.time.Instant;
import java.time.Period;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;

/** Issuing, listing and revoking API keys. */
@Service
public class ApiKeyAdministrationService {

    private final ApiKeyRepository keys;
    private final GrantableTargets targets;
    private final AuditLogService audit;
    private final Clock clock;
    private final UserRepository users;
    private final VisibilityService visibility;

    /**
     * Narrower than the column: the name is written beside the account's in every audit entry the
     * key causes, and that column is 255 wide too.
     */
    private static final int MAX_NAME_LENGTH = 100;

    public ApiKeyAdministrationService(
            ApiKeyRepository keys,
            GrantableTargets targets,
            AuditLogService audit,
            Clock clock,
            UserRepository users,
            VisibilityService visibility) {
        this.keys = keys;
        this.targets = targets;
        this.audit = audit;
        this.clock = clock;
        this.users = users;
        this.visibility = visibility;
    }

    /**
     * A key as it may be shown: never its hash.
     *
     * @param owner the account the key acts for; null for a key issued before keys had one, which
     *     authenticates nowhere any more and is shown so it can be revoked
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
            String owner,
            Instant createdAt,
            Instant lastUsedAt,
            Instant expiresAt,
            boolean expired) {}

    /** @param ownerUserId the account the key will act for — the one issuing it (decision 0024) */
    public record Request(
            String name, List<String> scopes, String targetKind, Long targetId, Integer expiresInDays, Long ownerUserId) {}

    /** @param secret the only occurrence of the plaintext */
    public record Issued(KeyView key, String secret) {}

    public record TargetOption(Long id, String label) {}

    public record TargetOptions(List<TargetOption> repositories, List<TargetOption> containers) {}

    public List<KeyView> list() {
        Instant asOf = clock.instant();
        GrantableTargets.Labels names = targets.labels();
        Map<Long, String> owners = new HashMap<>();
        users.findAll().forEach(user -> owners.put(user.getId(), user.getUsername()));
        return keys.findAllByOrderByCreatedAtDesc().stream()
                .map(key -> viewOf(key, asOf, names, owners))
                .toList();
    }

    /**
     * Issues a key and <b>returns it once</b>.
     *
     * <p>This is the only place the plaintext exists. An earlier implementation permanently
     * displayed the row's identifier as though it were the secret — so there had never been a
     * secret. Making it unrecoverable is the point.
     */
    public Issued issue(Request request, RequestActor actor) {
        String name = request.name() == null ? "" : request.name().trim();
        if (name.isEmpty()) {
            throw new InvalidInputException("A name is required.");
        }
        if (name.length() > MAX_NAME_LENGTH) {
            throw new InvalidApiKeyException("A key's name is at most " + MAX_NAME_LENGTH + " characters.");
        }

        List<ApiKeyScope> scopes = ApiKeys.normalizeScopes(request.scopes());
        Optional<Period> lifetime = ApiKeys.normalizeLifetime(request.expiresInDays());
        if (scopes.contains(ApiKeyScope.AGENT)) {
            // An agent's key is created with the agent, which binds it to that agent. Issued here
            // it would belong to nobody and authenticate nowhere.
            throw new InvalidApiKeyException("The agent scope is not issued here: declare the agent, which creates its key.");
        }
        if (request.ownerUserId() == null) {
            throw new IllegalStateException("An integration key is issued by an account, which it will act for.");
        }
        // The restriction is enforced again (decision 0024): the key acts for its account, narrowed
        // to this target, on the routes that accept a key.
        String targetKind = normalizeTargetKind(request);
        if (targetKind != null) {
            requireIssuerSees(request.ownerUserId(), targetKind, request.targetId());
        }

        ApiKeys.IssuedKey issued = ApiKeys.generate();
        Instant issuedAt = clock.instant();

        ApiKeyEntity key = new ApiKeyEntity();
        key.setName(name);
        key.setKeyHash(PasswordHasher.hash(issued.fullKey()));
        key.setPrefix(issued.prefix());
        key.setScopes(String.join(",", scopes.stream().map(ApiKeyScope::wireName).toList()));
        key.setCreatedAt(issuedAt);
        key.setExpiresAt(lifetime.map(issuedAt::plus).orElse(null));
        key.setOwnerUserId(request.ownerUserId());
        key.setTargetKind(targetKind);
        key.setTargetId(targetKind == null ? null : request.targetId());

        ApiKeyEntity saved = keys.save(key);
        record(actor, AuditOperation.API_KEY_CREATED, saved.getId().toString(),
                "API key issued: " + name + " (" + saved.getScopes() + ")");

        Map<Long, String> owner = users.findById(saved.getOwnerUserId())
                .map(user -> Map.of(user.getId(), user.getUsername()))
                .orElse(Map.of());
        return new Issued(viewOf(saved, issuedAt, targets.labels(), owner), issued.fullKey());
    }

    /**
     * The names of these keys, for a module that lists rows bound to a key (the declared SARIF
     * sources) to readers who may not open the key list — an auditor, a CISO. The name alone: it is
     * what the administrator wrote to say which pipeline holds the key, and the list shows it; the
     * prefix, the scopes, the owner and the target stay the key list's. A key revoked since is
     * missing from the map.
     *
     * <p><b>One lookup per {@link #LOOKUP_BATCH} ids</b>: the rows are sized by the data, and one bind
     * parameter per element fails past the PostgreSQL driver's 65,535.
     */
    public Map<UUID, String> names(Collection<UUID> ids) {
        if (ids == null || ids.isEmpty()) {
            return Map.of();
        }
        List<UUID> distinct = ids.stream().filter(Objects::nonNull).distinct().toList();
        Map<UUID, String> names = new HashMap<>();
        for (int from = 0; from < distinct.size(); from += LOOKUP_BATCH) {
            keys.findAllById(distinct.subList(from, Math.min(from + LOOKUP_BATCH, distinct.size())))
                    .forEach(key -> names.put(key.getId(), key.getName()));
        }
        return Map.copyOf(names);
    }

    /** How many identifiers one lookup binds: far under every engine's limit. */
    static final int LOOKUP_BATCH = 1_000;

    /**
     * A key as the list shows it, by id — for a module that binds a key to something of its own (a
     * declared SARIF source) and must check what the key is before it does.
     */
    public Optional<KeyView> key(UUID id) {
        Instant asOf = clock.instant();
        return keys.findById(id).map(key -> {
            Map<Long, String> owner = key.getOwnerUserId() == null
                    ? Map.of()
                    : users.findById(key.getOwnerUserId())
                            .filter(user -> Boolean.TRUE.equals(user.getIsActive()))
                            .map(user -> Map.of(user.getId(), user.getUsername()))
                            .orElse(Map.of());
            return viewOf(key, asOf, targets.labels(), owner);
        });
    }

    /**
     * @param actingAccountId the account revoking: only a platform governor revokes a governor's key
     */
    public void revoke(UUID id, Long actingAccountId, RequestActor actor) {
        ApiKeyEntity key = keys.findById(id).orElseThrow(() -> new NotFoundException("Key not found."));

        // **A governor's key is administered by a governor**, as its account is: an administrator
        // could not reset a governor's password, and could still revoke the key the governor's
        // pipeline signs in with — a denial of the role that lifts the rules the others act under,
        // one request away (the audit of 10 October 2026).
        if (key.getOwnerUserId() != null) {
            Optional<Role> owner = users.findById(key.getOwnerUserId()).flatMap(user -> Role.of(user.getRole()));
            Optional<Role> acting = actingAccountId == null
                    ? Optional.empty()
                    : users.findById(actingAccountId).flatMap(user -> Role.of(user.getRole()));
            AccountRules.refuseGovernorAdministration(acting, owner, Optional.empty()).ifPresent(refusal -> {
                throw new InvalidInputException(refusal);
            });
        }

        // Revoking deletes the row: a "disabled" key that a scan could re-enable by accident
        // would be worse than an absent one. The audit trail keeps the record.
        keys.deleteById(id);
        record(actor, AuditOperation.API_KEY_DELETED, id.toString(), "API key revoked: " + key.getName());
    }

    /** The targets a key can be restricted to, so the screen offers names rather than numbers. */
    public TargetOptions targets() {
        GrantableTargets.Labels labels = targets.labels();
        List<TargetOption> repositoryOptions = new ArrayList<>();
        labels.repositories().forEach((id, label) -> repositoryOptions.add(new TargetOption(id, label)));

        List<TargetOption> containerOptions = new ArrayList<>();
        labels.containers().forEach((id, label) -> containerOptions.add(new TargetOption(id, label)));

        return new TargetOptions(repositoryOptions, containerOptions);
    }

    /**
     * A restriction names a target that exists and that its account can see.
     *
     * <p>Not a hole otherwise — the account's visibility is intersected with the restriction when
     * the key is used — but a key restricted to nothing it can reach would pass issuance and then
     * list nothing, silently. Absent and hidden get the same answer, or issuing a key becomes a way
     * to probe which identifiers exist.
     */
    private void requireIssuerSees(Long ownerUserId, String targetKind, Long targetId) {
        ScanTarget target = "repository".equals(targetKind)
                ? new ScanTarget.Repository(targetId)
                : new ScanTarget.Container(targetId);
        boolean exists = targets.exists(target);
        boolean visible = exists && users.findById(ownerUserId)
                .map(owner -> visibility.of(UserView.of(owner)).permits(target))
                .orElse(false);
        if (!visible) {
            throw new InvalidApiKeyException("No " + targetKind + " " + targetId + " to restrict the key to.");
        }
    }

    /**
     * Empty for an unrestricted key; refused when the kind and the identifier disagree.
     *
     * <p>Kind and identifier are both required: a kind alone would be read as "everything of that
     * kind", which is not a restriction.
     */
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

    private static KeyView viewOf(ApiKeyEntity key, Instant asOf, GrantableTargets.Labels names, Map<Long, String> owners) {
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
                key.getOwnerUserId() == null ? null : owners.get(key.getOwnerUserId()),
                key.getCreatedAt(),
                key.getLastUsedAt(),
                key.getExpiresAt(),
                key.getExpiresAt() != null && !key.getExpiresAt().isAfter(asOf));
    }

    /** A target deleted since the key was issued: say so rather than showing a blank. */
    private static String targetLabel(ApiKeyEntity key, GrantableTargets.Labels names) {
        if (key.getTargetKind() == null || key.getTargetId() == null) {
            return null;
        }
        return "repository".equals(key.getTargetKind())
                ? names.repositories().getOrDefault(key.getTargetId(), key.getTargetKind() + " " + key.getTargetId() + " (deleted)")
                : names.containers().getOrDefault(key.getTargetId(), key.getTargetKind() + " " + key.getTargetId() + " (deleted)");
    }

    private void record(RequestActor actor, AuditOperation operation, String resourceId, String description) {
        audit.record(new AuditLogService.Record(
                operation, resourceId, description, actor.username(), actor.ipAddress(), actor.userAgent()));
    }
}

package com.asmolabs.vectispire.core.forges;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.forges.ForgeAddress;
import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionRefusal;
import com.asmolabs.vectispire.common.domain.forges.ForgeCredential;
import com.asmolabs.vectispire.common.domain.forges.ForgeEdition;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.forges.internal.ForgeClient;
import com.asmolabs.vectispire.core.forges.internal.ForgeProbes;
import com.asmolabs.vectispire.core.forges.internal.ForgeTargets;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Forge connections (decision 0037 §2): a read-only credential to a GitHub or a GitLab, probed against the
 * forge before it is kept, stored encrypted with its row as context, never read back out.
 *
 * <p><b>Probed on creation and on every change of what the token is presented to</b> — a new token, a new
 * pinned CA, a new network statement. The probe runs before any write and outside any transaction: it is
 * an outbound call of up to thirty seconds, and a row lock held across it is the incident this codebase
 * does not have.
 *
 * <p><b>Two refusals are recorded and signalled</b>, the ones that are how an attack through this form
 * looks: an address the outbound guard blocks and a token broader than read-only ({@code
 * FORGE_CONNECTION_REFUSED}, {@code VECTI-SEC-036}). The audit entry is written after the refusal and
 * outside any transaction, as every entry here is: {@link AuditLogService#record} opens its own.
 *
 * <p><b>The address cannot be changed.</b> Another server is another connection: the token was issued by
 * this one, and presenting it to a server typed later is the binding decision 0022 exists to keep.
 */
@Service
public class ForgeConnectionService {

    static final int NAME_LENGTH = 255;

    /** No forge issues a token within an order of magnitude of this; encrypted, it fits the column. */
    static final int MAX_TOKEN_LENGTH = 1_024;

    /**
     * GitHub's own rule for a login is narrower (letters, digits, single hyphens, 39 characters);
     * Enterprise Server's directory-synchronised logins may carry underscores and dots.
     */
    private static final Pattern GITHUB_OWNER = Pattern.compile("^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98})$");

    /** How the pinned CA's refusals name the field. */
    static final PinnedCa.Subject CA = ForgeTargets.CA;

    /**
     * What a connection's creation asks for.
     *
     * @param kind {@code github} or {@code gitlab}
     * @param baseUrl the web address; blank for github.com or gitlab.com
     * @param owner GitHub's organisation or user the token was issued for; refused for GitLab
     * @param internalNetwork the server is on the internal network: {@code INTERNAL_ALLOWED} rather than
     *     {@code PUBLIC_ONLY} — refused for a cloud edition
     * @param caPem the CA the server's certificate chains to, in place of the runtime's trust store; blank
     *     for that store — refused for a cloud edition
     */
    public record Creation(
            String name, String kind, String baseUrl, String owner, Boolean internalNetwork, String caPem, String token) {}

    /**
     * What a change asks for; a null component keeps what is stored.
     *
     * @param caPem blank unpins the CA, and the runtime's trust store applies again
     */
    public record Change(String name, Boolean internalNetwork, String caPem) {}

    private final ForgeConnectionRepository connections;
    private final ForgeDiscoveryRepository discoveries;
    private final ForgeRepositoryRepository snapshot;
    private final ForgeImportLinkRepository links;
    private final ForgeProbes probes;
    private final EncryptionService encryption;
    private final AuditLogService audit;
    private final Clock clock;
    private final TransactionTemplate transactions;

    public ForgeConnectionService(
            ForgeConnectionRepository connections,
            ForgeDiscoveryRepository discoveries,
            ForgeRepositoryRepository snapshot,
            ForgeImportLinkRepository links,
            ForgeProbes probes,
            EncryptionService encryption,
            AuditLogService audit,
            Clock clock,
            PlatformTransactionManager transactions) {
        this.connections = connections;
        this.discoveries = discoveries;
        this.snapshot = snapshot;
        this.links = links;
        this.probes = probes;
        this.encryption = encryption;
        this.audit = audit;
        this.clock = clock;
        this.transactions = new TransactionTemplate(transactions);
    }

    public List<ForgeConnectionView> list() {
        return connections.findAllByOrderByNameAsc().stream().map(this::viewOf).toList();
    }

    public ForgeConnectionView get(UUID id) {
        return viewOf(require(id));
    }

    /**
     * Probes the token against the forge, then keeps the connection.
     *
     * @throws InvalidInputException the request's form, with the sentence to show
     * @throws ForgeConnectionRefusal what the forge or the guard said, recorded when it is a security event
     */
    public ForgeConnectionView create(Creation request, RequestActor actor) {
        if (request == null) {
            throw new InvalidInputException("Describe the connection: a name, a forge and a token.");
        }
        String name = BoundedText.required(request.name(), NAME_LENGTH, "The name");
        ForgeKind kind = ForgeKind.parse(request.kind());
        ForgeAddress address = ForgeAddress.of(kind, request.baseUrl());
        String owner = ownerOf(kind, request.owner());
        boolean internal = Boolean.TRUE.equals(request.internalNetwork());
        Optional<PinnedCa> ca = caOf(request.caPem());
        refuseForCloud(address.edition(), internal, ca);
        String token = tokenOf(request.token());
        if (connections.existsByNameIgnoreCase(name)) {
            throw new InvalidInputException("A forge connection named \"" + name + "\" already exists.");
        }

        ForgeClient.Target target = new ForgeClient.Target(address, owner, policyOf(internal), ca);
        ForgeClient.Probe probe = probe(target, token, null, "Forge connection " + name + " refused", actor);

        Instant now = clock.instant();
        UUID id = UUID.randomUUID();
        ForgeConnectionEntity entity = new ForgeConnectionEntity();
        entity.setId(id);
        entity.setName(name);
        entity.setKind(kind.wireName());
        entity.setEdition(address.edition().wireName());
        entity.setBaseUrl(address.baseUrl());
        entity.setOwner(owner);
        entity.setInternalNetwork(internal);
        entity.setCaPem(ca.map(PinnedCa::pem).orElse(null));
        entity.setToken(encryption.encrypt(token, SecretCipher.forgeConnectionContext(id.toString())));
        apply(entity, probe, now);
        entity.setCreatedAt(now);
        entity.setCreatedBy(actorName(actor));
        entity.setUpdatedAt(now);
        entity.setUpdatedBy(actorName(actor));
        ForgeConnectionEntity saved;
        try {
            saved = connections.saveAndFlush(entity);
        } catch (DataIntegrityViolationException taken) {
            // Two administrators creating the same name at once: the second learns it here.
            throw new InvalidInputException("A forge connection named \"" + name + "\" already exists.");
        }
        record(actor, id, "Forge connection created: " + describe(saved), true);
        return viewOf(saved);
    }

    /**
     * Replaces the token in place, re-probed: the row and whatever hangs on it are kept (decision 0037 §2 —
     * 0022 rotates clone tokens by delete-and-add because nothing but repositories points at them; here the
     * discovery's snapshot and the imported targets' provenance will).
     */
    public ForgeConnectionView replaceToken(UUID id, String rawToken, RequestActor actor) {
        ForgeConnectionEntity entity = require(id);
        String token = tokenOf(rawToken);
        ForgeClient.Target target = targetOf(entity, entity.isInternalNetwork(), storedCa(entity));
        ForgeClient.Probe probe =
                probe(target, token, id, "Forge connection " + entity.getName() + ": new token refused", actor);

        Instant now = clock.instant();
        entity.setToken(encryption.encrypt(token, SecretCipher.forgeConnectionContext(id.toString())));
        apply(entity, probe, now);
        touch(entity, actor, now);
        ForgeConnectionEntity saved = connections.save(entity);
        record(actor, id, "Forge connection token replaced: " + describe(saved), true);
        return viewOf(saved);
    }

    /**
     * Renames a connection, or changes what its token is presented through — the network statement, the
     * pinned CA — which is probed again with the stored token first.
     *
     * <p><b>Saving re-seals the token</b> under the current {@code ENCRYPTION_KEY} when it was still sealed
     * under a previous one: that is how a key rotation reaches this store, as re-saving reaches the others
     * ({@code KEY_ROTATION.md}).
     */
    public ForgeConnectionView update(UUID id, Change change, RequestActor actor) {
        ForgeConnectionEntity entity = require(id);
        if (change == null) {
            throw new InvalidInputException("Say what changes: the name, the network statement or the CA.");
        }
        ForgeEdition edition = editionOf(entity);
        String name = change.name() == null ? entity.getName() : BoundedText.required(change.name(), NAME_LENGTH, "The name");
        boolean internal = change.internalNetwork() == null ? entity.isInternalNetwork() : change.internalNetwork();
        Optional<PinnedCa> ca = change.caPem() == null ? storedCa(entity) : caOf(change.caPem());
        refuseForCloud(edition, internal, ca);
        if (!name.equalsIgnoreCase(entity.getName()) && connections.existsByNameIgnoreCaseAndIdNot(name, id)) {
            throw new InvalidInputException("A forge connection named \"" + name + "\" already exists.");
        }
        boolean trustChanged = internal != entity.isInternalNetwork()
                || !Optional.ofNullable(entity.getCaPem()).equals(ca.map(PinnedCa::pem));

        String context = SecretCipher.forgeConnectionContext(id.toString());
        SecretCipher.Decrypted sealed = encryption.inspect(entity.getToken(), context);
        Instant now = clock.instant();
        if (trustChanged) {
            if (sealed.state() == SecretCipher.SecretState.UNREADABLE) {
                throw new InvalidInputException("The token can no longer be decrypted by any configured key: replace "
                        + "it first, then change how it is presented.");
            }
            ForgeClient.Probe probe = probe(targetOf(entity, internal, ca), sealed.plainText(), id,
                    "Forge connection " + entity.getName() + ": change refused", actor);
            apply(entity, probe, now);
        }
        if (sealed.state() == SecretCipher.SecretState.PREVIOUS_KEY) {
            entity.setToken(encryption.encrypt(sealed.plainText(), context));
        }
        String previousName = entity.getName();
        entity.setName(name);
        entity.setInternalNetwork(internal);
        entity.setCaPem(ca.map(PinnedCa::pem).orElse(null));
        touch(entity, actor, now);
        ForgeConnectionEntity saved;
        try {
            saved = connections.saveAndFlush(entity);
        } catch (DataIntegrityViolationException taken) {
            throw new InvalidInputException("A forge connection named \"" + name + "\" already exists.");
        }
        String what = (previousName.equals(name) ? "" : "renamed from " + previousName + "; ")
                + (trustChanged ? "presented " + (internal ? "on the internal network" : "on the public network")
                        + ca.map(pinned -> ", CA \"" + pinned.subject() + "\" pinned").orElse(", runtime trust store")
                        + "; " : "")
                + (sealed.state() == SecretCipher.SecretState.PREVIOUS_KEY ? "token re-sealed under the current key; " : "");
        record(actor, id, "Forge connection updated: " + what + describe(saved), trustChanged);
        return viewOf(saved);
    }

    /**
     * Deletes a connection with its discoveries, its snapshot and its provenance links, in one transaction. No target
     * goes with it — an imported repository is a target like any other from the moment it is created (decision 0037
     * §5); it only stops saying where it came from.
     *
     * <p><b>The discoveries first.</b> A running discovery writes each page in a transaction that first renews its
     * lease, holding its row: deleting the runs waits for that page to commit, so that the snapshot's deletion, which
     * follows, sees the page's rows rather than leaving them behind a connection that no longer exists. The run then
     * finds its lease gone and stops.
     */
    public void delete(UUID id, RequestActor actor) {
        ForgeConnectionEntity entity = require(id);
        transactions.executeWithoutResult(status -> {
            discoveries.deleteByConnection(id);
            snapshot.deleteByConnection(id);
            links.deleteByConnection(id);
            connections.deleteById(id);
        });
        record(actor, id, "Forge connection deleted: " + describe(entity), true);
    }

    private ForgeClient.Probe probe(
            ForgeClient.Target target, String token, UUID id, String refusal, RequestActor actor) {
        try {
            return probes.probe(target, token);
        } catch (ForgeConnectionRefusal refused) {
            if (refused.reason().signalled()) {
                audit.record(actor.entry(
                        AuditOperation.FORGE_CONNECTION_REFUSED,
                        id == null ? null : id.toString(),
                        refusal + " (" + refused.reason().name().toLowerCase(Locale.ROOT) + ", "
                                + target.address().edition().label() + " at " + target.address().baseUrl() + "): "
                                + refused.getMessage()));
            }
            throw refused;
        }
    }

    private static void apply(ForgeConnectionEntity entity, ForgeClient.Probe probe, Instant now) {
        ForgeCredential credential = probe.credential();
        entity.setCredentialKind(credential.kind().wireName());
        entity.setScopes(credential.scopes().map(scopes -> String.join(",", scopes)).orElse(null));
        entity.setCanWrite(credential.canWrite().orElse(null));
        entity.setTokenExpiresAt(probe.expiresAt().orElse(null));
        entity.setForgeVersion(probe.version().map(version -> BoundedText.clip(version, 64)).orElse(null));
        entity.setProbedAt(now);
    }

    private void touch(ForgeConnectionEntity entity, RequestActor actor, Instant now) {
        entity.setUpdatedAt(now);
        entity.setUpdatedBy(actorName(actor));
    }

    private void record(RequestActor actor, UUID id, String description, boolean signalled) {
        AuditLogService.Record entry = actor.entry(AuditOperation.FORGE_CONNECTION_CHANGED, id.toString(), description);
        audit.record(signalled ? entry.signalling(SecurityEventType.FORGE_CONNECTION_CHANGED) : entry);
    }

    /**
     * What an audit entry and a SIEM event say about a connection: the forge, the address, the credential
     * and whether it can write — the owner's answer 2 wants a classic token's write access in both — and
     * never the token.
     */
    private static String describe(ForgeConnectionEntity entity) {
        return entity.getName() + " (" + editionOf(entity).label() + " at " + entity.getBaseUrl()
                + (entity.getOwner() == null ? "" : ", owner " + entity.getOwner())
                + (entity.isInternalNetwork() ? ", internal network" : "")
                + (entity.getCaPem() == null ? "" : ", CA pinned")
                + "; " + entity.getCredentialKind().replace('_', ' ') + " token"
                + (entity.getScopes() == null ? ", permissions not reported" : ", scopes " + entity.getScopes())
                + (Boolean.TRUE.equals(entity.getCanWrite()) ? ", CAN WRITE" : "") + ")";
    }

    private ForgeConnectionView viewOf(ForgeConnectionEntity entity) {
        Optional<PinnedCa> ca = Optional.ofNullable(entity.getCaPem()).map(pem -> PinnedCa.read(pem, CA));
        return new ForgeConnectionView(
                entity.getId(),
                entity.getName(),
                entity.getKind(),
                entity.getEdition(),
                entity.getBaseUrl(),
                entity.getOwner(),
                entity.isInternalNetwork(),
                ca.map(PinnedCa::subject).orElse(null),
                ca.map(PinnedCa::notAfter).orElse(null),
                entity.getCredentialKind(),
                entity.getScopes() == null ? null : Arrays.asList(entity.getScopes().split(",")),
                entity.getCanWrite(),
                entity.getTokenExpiresAt(),
                entity.getForgeVersion(),
                entity.getProbedAt(),
                encryption.inspect(entity.getToken(), SecretCipher.forgeConnectionContext(entity.getId().toString()))
                        .state()
                        .name()
                        .toLowerCase(Locale.ROOT),
                entity.getCreatedAt(),
                entity.getCreatedBy(),
                entity.getUpdatedAt(),
                entity.getUpdatedBy(),
                discoveries.findFirstByConnectionIdOrderByRequestedAtDescIdDesc(entity.getId())
                        .map(ForgeDiscoveryService::view)
                        .orElse(null),
                links.countByConnectionId(entity.getId()));
    }

    private ForgeConnectionEntity require(UUID id) {
        return connections.findById(id).orElseThrow(() -> new NotFoundException("Forge connection not found."));
    }

    private ForgeClient.Target targetOf(ForgeConnectionEntity entity, boolean internal, Optional<PinnedCa> ca) {
        return ForgeTargets.of(entity, internal, ca);
    }

    private Optional<PinnedCa> storedCa(ForgeConnectionEntity entity) {
        return ForgeTargets.storedCa(entity, clock.instant());
    }

    private Optional<PinnedCa> caOf(String pem) {
        return pem == null || pem.isBlank() ? Optional.empty() : Optional.of(PinnedCa.parse(pem, clock.instant(), CA));
    }

    private static ForgeEdition editionOf(ForgeConnectionEntity entity) {
        return ForgeEdition.valueOf(entity.getEdition().toUpperCase(Locale.ROOT));
    }

    private static OutboundPolicy policyOf(boolean internal) {
        return ForgeTargets.policyOf(internal);
    }

    private static void refuseForCloud(ForgeEdition edition, boolean internal, Optional<PinnedCa> ca) {
        if (!edition.cloud()) {
            return;
        }
        if (internal) {
            throw new InvalidInputException(edition.label() + " is not on your internal network: the statement is for "
                    + "a server you host.");
        }
        if (ca.isPresent()) {
            throw new InvalidInputException(edition.label() + " is verified against the public CAs: a pinned CA is for "
                    + "a server you host.");
        }
    }

    private static String ownerOf(ForgeKind kind, String raw) {
        String owner = raw == null ? "" : raw.trim();
        return switch (kind) {
            case GITHUB -> {
                if (owner.isEmpty()) {
                    throw new InvalidInputException("A GitHub connection names the organisation or user its token was "
                            + "issued for.");
                }
                if (!GITHUB_OWNER.matcher(owner).matches()) {
                    throw new InvalidInputException("\"" + BoundedText.clip(owner, 100)
                            + "\" is not a GitHub organisation or user name.");
                }
                yield owner;
            }
            case GITLAB -> {
                if (!owner.isEmpty()) {
                    throw new InvalidInputException("A GitLab connection names no owner: the groups its token can read "
                            + "are discovered.");
                }
                yield null;
            }
        };
    }

    private static String tokenOf(String raw) {
        String token = raw == null ? "" : raw.trim();
        if (token.isEmpty()) {
            throw new InvalidInputException("The token is required.");
        }
        BoundedText.within(token, MAX_TOKEN_LENGTH, "The token");
        if (token.chars().anyMatch(Character::isWhitespace)) {
            // A pasted line break or a "Bearer " prefix: the forge would refuse it as a bad token.
            throw new InvalidInputException("The token contains spaces or line breaks: paste the token alone.");
        }
        return token;
    }

    private static String actorName(RequestActor actor) {
        return actor.username() == null ? "unknown" : BoundedText.clip(actor.username(), 255);
    }
}

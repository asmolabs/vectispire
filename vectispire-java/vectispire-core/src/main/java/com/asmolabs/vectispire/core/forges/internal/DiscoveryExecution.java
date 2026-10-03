package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.forges.DiscoveredRepository;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryReason;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryState;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import com.asmolabs.vectispire.common.domain.net.UnsafeUrlException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * One claimed discovery, carried out (decision 0037 §3): the connection read as stored, its forge listed through the
 * pager, each page written into the snapshot and compared with it, and the run ended in the state what happened
 * calls for.
 *
 * <p><b>The connection is read again at the claim</b> — its address re-derived and re-validated at every request by
 * the outbound guard, since the name may resolve elsewhere by now; its pinned CA checked current; its token
 * decrypted for this run alone. A token no key decrypts, a CA that expired: the run fails {@code
 * connection_unusable}, and the administrator replaces what is stored.
 *
 * <p><b>Each page is written in a transaction that first renews the lease</b>, and is rolled back when the run is no
 * longer this instance's: a page read by an instance whose lease lapsed, or whose connection was deleted meanwhile,
 * must not reappear in a snapshot that has moved on — or that no longer exists.
 *
 * <p><b>Ended by what stopped it.</b> A bound — time, repositories, a rate limit longer than a minute — ends it
 * {@code partial}: what it read is kept and compared, and nothing is marked gone. A rejected token, a refused
 * address, a forge that does not answer end it {@code failed}. A next page on another origin, or an address the
 * guard refuses, ends it {@code failed} <em>and</em> is recorded {@code FORGE_CONNECTION_REFUSED} — signalled {@code
 * VECTI-SEC-036} — in the requester's name: it is how a forge pointing the token elsewhere, or a name rebound to
 * the internal network, shows itself. Only {@code completed} marks gone what the run did not list.
 */
@Component
public class DiscoveryExecution {

    private static final Logger log = LoggerFactory.getLogger(DiscoveryExecution.class);

    /** How often, at most, a run renews its lease between pages: before a request, when this long has passed. */
    static final Duration RENEWAL = Duration.ofSeconds(15);

    private final ForgeDiscoveryRepository discoveries;
    private final ForgeRepositoryRepository repositories;
    private final ForgeConnectionRepository connections;
    private final EncryptionService encryption;
    private final OutboundJson outbound;
    private final Map<ForgeKind, ForgeLister> listers = new EnumMap<>(ForgeKind.class);
    private final DiscoveryBounds bounds;
    private final AuditLogService audit;
    private final Clock clock;
    private final TransactionTemplate transactions;

    public DiscoveryExecution(
            ForgeDiscoveryRepository discoveries,
            ForgeRepositoryRepository repositories,
            ForgeConnectionRepository connections,
            EncryptionService encryption,
            OutboundJson outbound,
            List<ForgeLister> listers,
            DiscoveryBounds bounds,
            AuditLogService audit,
            Clock clock,
            PlatformTransactionManager transactions) {
        this.discoveries = discoveries;
        this.repositories = repositories;
        this.connections = connections;
        this.encryption = encryption;
        this.outbound = outbound;
        listers.forEach(lister -> this.listers.put(lister.kind(), lister));
        this.bounds = bounds;
        this.audit = audit;
        this.clock = clock;
        this.transactions = new TransactionTemplate(transactions);
    }

    /** Whether this version lists the repositories of a forge of this kind. */
    public boolean lists(ForgeKind kind) {
        return listers.containsKey(kind);
    }

    /** Carries out the run {@code owner} claimed, to its end — or to the moment it learns the run is no longer its. */
    public void execute(long id, String owner) {
        ForgeDiscoveryEntity entity = discoveries.findById(id).orElse(null);
        if (entity == null || !owner.equals(entity.getClaimedBy())) {
            return;
        }
        Run run = new Run(entity, owner);
        Outcome outcome;
        try {
            run.open().list(run);
            outcome = new Outcome(DiscoveryState.COMPLETED, null, null, null);
        } catch (LeaseLost lost) {
            log.info("Forge discovery {} is no longer this instance's ({}); left to its new owner.", id, owner);
            return;
        } catch (ForgeLister.RepositoryBoundReached bound) {
            outcome = Outcome.of(DiscoveryReason.REPOSITORY_BOUND, bound.getMessage());
        } catch (OutboundPager.DeadlineReachedException late) {
            outcome = Outcome.of(DiscoveryReason.TIME_BOUND, "The discovery reached its bound of "
                    + bounds.maxDuration().toMinutes() + " minutes; what it listed is kept, nothing is marked gone.");
        } catch (OutboundPager.RateLimitedException limited) {
            outcome = new Outcome(DiscoveryState.PARTIAL, DiscoveryReason.RATE_LIMITED, limited.getMessage()
                    + " What was listed is kept; run the discovery again once the limit lifts.", limited.liftsAt());
        } catch (OutboundPager.CrossOriginPageException elsewhere) {
            outcome = Outcome.of(DiscoveryReason.CROSS_ORIGIN_PAGE, elsewhere.getMessage());
        } catch (UnsafeUrlException blocked) {
            outcome = Outcome.of(DiscoveryReason.DESTINATION_BLOCKED, blocked.getMessage());
        } catch (OutboundJson.OutboundFailureException unanswered) {
            outcome = Outcome.of(DiscoveryReason.FORGE_UNAVAILABLE, unanswered.getMessage());
        } catch (ForgeListingException refused) {
            outcome = Outcome.of(refused.reason(), refused.getMessage());
        } catch (RuntimeException unforeseen) {
            log.error("Forge discovery {} failed unexpectedly: {}", id, unforeseen.getMessage(), unforeseen);
            outcome = Outcome.of(DiscoveryReason.INTERNAL_ERROR,
                    "The discovery stopped on an error this version did not foresee; the control plane's log has it.");
        }
        if (run.finish(outcome) && (outcome.reason() == DiscoveryReason.CROSS_ORIGIN_PAGE
                || outcome.reason() == DiscoveryReason.DESTINATION_BLOCKED)) {
            audit.record(new RequestActor(entity.getRequestedBy(), null, null).entry(
                    AuditOperation.FORGE_CONNECTION_REFUSED,
                    entity.getConnectionId().toString(),
                    "Forge discovery " + id + " stopped (" + outcome.reason().wireName() + ", " + run.where() + "): "
                            + outcome.detail()));
        }
    }

    /** How a run ended. */
    record Outcome(DiscoveryState state, DiscoveryReason reason, String detail, Instant rateLimitResetAt) {

        static Outcome of(DiscoveryReason reason, String detail) {
            return new Outcome(reason.state(), reason, detail, null);
        }
    }

    /** The run's lease is no longer this instance's: stop, write nothing more. */
    static final class LeaseLost extends RuntimeException {

        private static final long serialVersionUID = 1L;

        LeaseLost() {
            super("The discovery's lease is no longer held.");
        }
    }

    /** One run's state while it lists: what the listing writes to. */
    private final class Run implements ForgeLister.Listing {

        private final long id;
        private final UUID connectionId;
        private final String owner;
        private final Set<String> namespaces = new HashSet<>();
        private final Set<String> listed = new HashSet<>();
        private final Set<String> languages = new LinkedHashSet<>();
        private final List<OutboundPager> pagers = new ArrayList<>();
        private ForgeClient.Target target;
        private String token;
        private Instant deadline;
        private Instant renewed;
        private int skipped;

        Run(ForgeDiscoveryEntity entity, String owner) {
            this.id = entity.getId();
            this.connectionId = entity.getConnectionId();
            this.owner = owner;
            this.renewed = clock.instant();
        }

        /** Reads the connection as it is stored now, and the adapter that lists it. */
        ForgeLister open() {
            ForgeConnectionEntity connection = connections.findById(connectionId).orElseThrow(LeaseLost::new);
            ForgeKind kind = ForgeKind.parse(connection.getKind());
            ForgeLister lister = listers.get(kind);
            if (lister == null) {
                throw new ForgeListingException(DiscoveryReason.UNSUPPORTED, "This version does not list the "
                        + "repositories of " + kind.wireName() + " connections yet.");
            }
            Instant now = clock.instant();
            Optional<PinnedCa> ca;
            try {
                ca = ForgeTargets.storedCa(connection, now);
            } catch (InvalidInputException unusable) {
                throw new ForgeListingException(DiscoveryReason.CONNECTION_UNUSABLE, unusable.getMessage()
                        + " Replace the CA on the connection.");
            }
            SecretCipher.Decrypted sealed = encryption.inspect(connection.getToken(),
                    SecretCipher.forgeConnectionContext(connectionId.toString()));
            if (sealed.state() == SecretCipher.SecretState.UNREADABLE) {
                throw new ForgeListingException(DiscoveryReason.CONNECTION_UNUSABLE, "The connection's token can no "
                        + "longer be decrypted by any configured key: replace it on the connection.");
            }
            this.token = sealed.plainText();
            this.target = ForgeTargets.of(connection, connection.isInternalNetwork(), ca);
            this.deadline = now.plus(bounds.maxDuration());
            return lister;
        }

        String where() {
            return target == null ? "connection " + connectionId
                    : target.address().edition().label() + " at " + target.address().baseUrl();
        }

        @Override
        public ForgeClient.Target target() {
            return target;
        }

        @Override
        public String token() {
            return token;
        }

        @Override
        public OutboundPager pager(Map<String, String> credential) {
            OutboundPager pager = outbound.pager(new OutboundPager.Settings(target.address().apiRoot(), target.policy(),
                    where(), credential, target.trust(), deadline, bounds.maxRateLimitWait(), OutboundJson.TIMEOUT,
                    this::heartbeat), clock, OutboundPager.Sleeper.REAL);
            pagers.add(pager);
            return pager;
        }

        @Override
        public void namespace(String path) {
            if (path != null) {
                namespaces.add(path);
            }
        }

        @Override
        public void repositories(List<DiscoveredRepository> page) {
            // One forge id once per run, should a page repeat one: a keyset listing should not, an offset one may.
            Map<String, DiscoveredRepository> fresh = new LinkedHashMap<>();
            for (DiscoveredRepository repository : page) {
                if (!listed.contains(repository.forgeId())) {
                    fresh.putIfAbsent(repository.forgeId(), repository);
                }
            }
            int room = bounds.maxRepositories() - listed.size();
            List<DiscoveredRepository> kept = fresh.values().stream().limit(Math.max(0, room)).toList();
            transactions.executeWithoutResult(status -> {
                renewOrStop();
                write(kept);
            });
            if (fresh.size() > room) {
                throw new ForgeLister.RepositoryBoundReached("The discovery stopped at " + bounds.maxRepositories()
                        + " repositories, its bound; the rest were not listed, and nothing is marked gone.");
            }
        }

        @Override
        public List<String> languagesWanted() {
            return List.copyOf(languages);
        }

        @Override
        public void language(String forgeId, String language) {
            String value = language == null || language.isBlank()
                    || language.length() > DiscoveredRepository.LANGUAGE_LENGTH ? null : language;
            repositories.setLanguage(connectionId, forgeId, value);
        }

        /** The page's repositories into the snapshot, each compared with what the snapshot knew. */
        private void write(List<DiscoveredRepository> page) {
            List<DiscoveredRepository> storable = new ArrayList<>();
            for (DiscoveredRepository repository : page) {
                if (repository.unstorable().isPresent()) {
                    skipped++;
                    log.warn("Forge discovery {}: repository {} not kept — {}.", id,
                            BoundedText.clip(repository.forgeId(), 64), repository.unstorable().get());
                } else {
                    storable.add(repository.bounded());
                }
            }
            if (storable.isEmpty()) {
                return;
            }
            Map<String, ForgeRepositoryEntity> known = repositories
                    .findByConnectionIdAndForgeIdIn(connectionId,
                            storable.stream().map(DiscoveredRepository::forgeId).toList())
                    .stream()
                    .collect(Collectors.toMap(ForgeRepositoryEntity::getForgeId, Function.identity()));
            Instant now = clock.instant();
            List<ForgeRepositoryEntity> rows = new ArrayList<>();
            for (DiscoveredRepository repository : storable) {
                ForgeRepositoryEntity row = known.get(repository.forgeId());
                if (row == null) {
                    row = new ForgeRepositoryEntity();
                    row.setConnectionId(connectionId);
                    row.setForgeId(repository.forgeId());
                    row.setFirstSeenBy(id);
                    row.setFirstSeenAt(now);
                    languages.add(repository.forgeId());
                } else {
                    // Compared with the previous run's reading — not with this run's own, which a resumed attempt
                    // already wrote: its changes were counted then.
                    boolean earlierRun = row.getLastSeenBy() != id && row.getFirstSeenBy() != id;
                    if (earlierRun) {
                        List<String> changes = repository.changesSince(row.getFullPath(), row.getDefaultBranch(),
                                row.getArchived(), row.getGoneBy() != null);
                        if (!changes.isEmpty()) {
                            row.setChangedBy(id);
                            row.setChangeSummary(BoundedText.clip(String.join("; ", changes), 1500));
                        }
                    }
                    if (!Objects.equals(row.getLastActivityAt(), repository.lastActivityAt())
                            || (row.getLastSeenBy() == id && row.getLanguage() == null)) {
                        languages.add(repository.forgeId());
                    }
                }
                listed.add(repository.forgeId());
                apply(row, repository);
                row.setLastSeenBy(id);
                row.setLastSeenAt(now);
                row.setGoneBy(null);
                row.setGoneAt(null);
                rows.add(row);
            }
            repositories.saveAll(rows);
        }

        /** The listing's facts onto the row — the language aside: it is asked after the listing, or kept. */
        private void apply(ForgeRepositoryEntity row, DiscoveredRepository repository) {
            row.setFullPath(repository.fullPath());
            row.setNamespacePath(repository.namespacePath());
            row.setPersonal(repository.personal());
            row.setName(repository.name());
            row.setDefaultBranch(repository.defaultBranch());
            row.setArchived(repository.archived());
            row.setFork(repository.fork());
            row.setVisibility(repository.visibility() == null ? null : repository.visibility().toLowerCase(Locale.ROOT));
            row.setLastActivityAt(repository.lastActivityAt());
            row.setSizeBytes(repository.sizeBytes());
            row.setHttpUrl(repository.httpUrl());
            row.setSshUrl(repository.sshUrl());
            row.setWebUrl(repository.webUrl());
        }

        /** Before every request: the lease renewed, and the progress written, when {@link #RENEWAL} has passed. */
        private void heartbeat() {
            if (Duration.between(renewed, clock.instant()).compareTo(RENEWAL) >= 0) {
                renewOrStop();
            }
        }

        private void renewOrStop() {
            Instant now = clock.instant();
            if (discoveries.renew(id, DiscoveryState.RUNNING.wireName(), owner, now.plus(DiscoveryQueue.LEASE),
                    namespaces.size(), listed.size(), skipped, requests(), waitedSeconds()) != 1) {
                throw new LeaseLost();
            }
            renewed = now;
        }

        private int requests() {
            return pagers.stream().mapToInt(OutboundPager::requests).sum();
        }

        private long waitedSeconds() {
            return pagers.stream().map(OutboundPager::rateLimitWaited).reduce(Duration.ZERO, Duration::plus).toSeconds();
        }

        /**
         * Ends the run, with the comparison: gone marked when — and only when — it completed, new and changed
         * counted whatever the end. Rolled back whole when the run is no longer this instance's. Whether it ended.
         */
        boolean finish(Outcome outcome) {
            Instant now = clock.instant();
            Boolean ended = transactions.execute(status -> {
                Integer gone = outcome.state() == DiscoveryState.COMPLETED
                        ? repositories.markGone(connectionId, id, now) : null;
                int newCount = (int) repositories.countByConnectionIdAndFirstSeenBy(connectionId, id);
                int changedCount = (int) repositories.countByConnectionIdAndChangedBy(connectionId, id);
                int finished = discoveries.finish(id, DiscoveryState.RUNNING.wireName(), owner,
                        outcome.state().wireName(), outcome.reason() == null ? null : outcome.reason().wireName(),
                        outcome.detail() == null ? null : BoundedText.clip(outcome.detail(), 2000), now,
                        namespaces.size(), listed.size(), skipped, requests(), waitedSeconds(),
                        outcome.rateLimitResetAt(), newCount, changedCount, gone);
                if (finished != 1) {
                    status.setRollbackOnly();
                    return false;
                }
                return true;
            });
            boolean done = Boolean.TRUE.equals(ended);
            if (done) {
                log.info("Forge discovery {} {}{}: {} namespaces, {} repositories, {} requests.", id,
                        outcome.state().wireName(), outcome.reason() == null ? "" : " (" + outcome.reason().wireName() + ")",
                        namespaces.size(), listed.size(), requests());
            }
            return done;
        }
    }
}

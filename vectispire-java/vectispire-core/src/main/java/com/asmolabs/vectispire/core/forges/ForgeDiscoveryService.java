package com.asmolabs.vectispire.core.forges;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryReason;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryState;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.forges.UnreadableNamespace;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.forges.internal.DiscoveryExecution;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import java.time.Clock;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * A connection's discoveries (decision 0037 §3): requested, queued for a control-plane instance, polled while they
 * run, and the snapshot they compared themselves with, read per run.
 *
 * <p><b>Queued, never run in the request.</b> A discovery of three thousand projects is minutes of pages and a
 * language request per project; a request held that long is cut by the first proxy, and a restart in the middle
 * would leave no trace. So the request writes a {@code pending} row and answers at once; an instance claims it
 * (see {@code DiscoveryWorker}).
 *
 * <p><b>One per connection at a time.</b> The connection's id is the run's active key, unique while it is pending
 * or running: a second request is answered with the first one's id. A refused insert is not read as that answer
 * until the committed row says so — a lock timeout or a dropped connection fail an insert too.
 *
 * <p><b>A queued discovery is audited</b> ({@code FORGE_DISCOVERY_REQUESTED}, in the requester's name, after the
 * commit): it reads the name of every repository an organisation holds. A refused request queues nothing and
 * records nothing.
 */
@Service
public class ForgeDiscoveryService {

    /** A connection's runs, newest first: a screen's page, not its history. */
    static final int LISTED = 50;

    /** The largest page of the snapshot a request reads. */
    static final int MAX_LIMIT = 500;

    /** Which repositories of a run a reader asks for. */
    public enum Change {
        /** Every repository the run listed. */
        ALL,
        /** Listed for the first time by the run. */
        NEW,
        /** Found renamed or moved, with another default branch, archived, unarchived, or back after being gone. */
        CHANGED,
        /** No longer listed by the run, which completed — the only kind of run that says so. */
        GONE;

        /** A reader's word; blank is {@link #ALL}. */
        static Change parse(String raw) {
            if (raw == null || raw.isBlank()) {
                return ALL;
            }
            return switch (raw.trim().toLowerCase(Locale.ROOT)) {
                case "all" -> ALL;
                case "new" -> NEW;
                case "changed" -> CHANGED;
                case "gone" -> GONE;
                default -> throw new InvalidInputException("\"" + BoundedText.clip(raw.trim(), 40)
                        + "\" is not a change: all, new, changed or gone.");
            };
        }
    }

    /** One page of a run's repositories. */
    public record RepositoryPage(List<ForgeRepositoryView> items, long total, int limit, int offset) {}

    private final ForgeConnectionRepository connections;
    private final ForgeDiscoveryRepository discoveries;
    private final ForgeRepositoryRepository repositories;
    private final DiscoveryExecution execution;
    private final AuditLogService audit;
    private final Clock clock;
    private final TransactionTemplate transactions;

    public ForgeDiscoveryService(
            ForgeConnectionRepository connections,
            ForgeDiscoveryRepository discoveries,
            ForgeRepositoryRepository repositories,
            DiscoveryExecution execution,
            AuditLogService audit,
            Clock clock,
            PlatformTransactionManager transactions) {
        this.connections = connections;
        this.discoveries = discoveries;
        this.repositories = repositories;
        this.execution = execution;
        this.audit = audit;
        this.clock = clock;
        this.transactions = new TransactionTemplate(transactions);
    }

    /**
     * Queues a discovery of the connection.
     *
     * @throws NotFoundException "Forge connection not found."
     * @throws ForgeDiscoveryConflict {@code forge-discovery-in-progress} with the running one's {@code discoveryId};
     *     {@code forge-discovery-unsupported} for a forge this version does not list
     */
    public ForgeDiscoveryView request(UUID connectionId, RequestActor actor) {
        ForgeConnectionEntity connection = requireConnection(connectionId);
        ForgeKind kind = ForgeKind.parse(connection.getKind());
        if (!execution.lists(kind)) {
            throw new ForgeDiscoveryConflict(ForgeDiscoveryConflict.Cause.UNSUPPORTED, "This version does not discover "
                    + "the repositories of a " + kind.wireName() + " connection yet.");
        }
        String key = connectionId.toString();
        ForgeDiscoveryEntity saved;
        try {
            saved = transactions.execute(status -> {
                discoveries.findByActiveKey(key).ifPresent(running -> {
                    throw inProgress(running);
                });
                ForgeDiscoveryEntity run = new ForgeDiscoveryEntity();
                run.setConnectionId(connectionId);
                run.setState(DiscoveryState.PENDING.wireName());
                run.setActiveKey(key);
                run.setRequestedAt(clock.instant());
                run.setRequestedBy(actor.username() == null ? "unknown" : BoundedText.clip(actor.username(), 255));
                return discoveries.saveAndFlush(run);
            });
        } catch (DataAccessException refused) {
            // The unique key refuses the second of two racing requests — and a lock timeout or a dropped connection
            // fail an insert too. Only the committed row says which.
            Optional<ForgeDiscoveryEntity> running = discoveries.findByActiveKey(key);
            if (running.isPresent()) {
                throw inProgress(running.get());
            }
            throw refused;
        }
        // After the commit, as every entry here: the log opens a transaction of its own.
        audit.record(actor.entry(AuditOperation.FORGE_DISCOVERY_REQUESTED, connectionId.toString(),
                "Forge discovery " + saved.getId() + " requested of connection " + connection.getName() + " ("
                        + connectionId + ", " + kind.wireName() + " at " + connection.getBaseUrl()
                        + "): queued for the control plane."));
        return view(saved);
    }

    /** The connection's discoveries, newest first. */
    public List<ForgeDiscoveryView> list(UUID connectionId) {
        requireConnection(connectionId);
        return discoveries.findByConnectionIdOrderByRequestedAtDescIdDesc(connectionId, PageRequest.of(0, LISTED))
                .stream().map(ForgeDiscoveryService::view).toList();
    }

    /** One discovery of the connection; the connection's 404 first, then the run's. */
    public ForgeDiscoveryView get(UUID connectionId, long discoveryId) {
        return view(requireDiscovery(connectionId, discoveryId));
    }

    /** The connection's latest discovery, for its listing; empty before the first. */
    Optional<ForgeDiscoveryView> latest(UUID connectionId) {
        return discoveries.findFirstByConnectionIdOrderByRequestedAtDescIdDesc(connectionId)
                .map(ForgeDiscoveryService::view);
    }

    /**
     * A page of the repositories a run listed, found new, changed or gone, by full path. Gone is a completed run's
     * word only: asked of any other run, it is refused rather than answered empty — an empty list would say that
     * nothing went.
     */
    public RepositoryPage repositories(UUID connectionId, long discoveryId, String change, Integer limit, Integer offset) {
        ForgeDiscoveryEntity run = requireDiscovery(connectionId, discoveryId);
        Change wanted = Change.parse(change);
        int size = limit == null ? 100 : limit;
        int from = offset == null ? 0 : offset;
        if (size < 1 || size > MAX_LIMIT) {
            throw new InvalidInputException("The limit is between 1 and " + MAX_LIMIT + ".");
        }
        if (from < 0 || from % size != 0) {
            throw new InvalidInputException("The offset is zero or a multiple of the limit.");
        }
        if (wanted == Change.GONE && DiscoveryState.ofStored(run.getState()) != DiscoveryState.COMPLETED) {
            throw new InvalidInputException("Only a completed discovery says which repositories are gone; this one is "
                    + run.getState() + DiscoveryReason.ofStored(run.getReason()).map(r -> " (" + r.wireName() + ")")
                    .orElse("") + ".");
        }
        PageRequest page = PageRequest.of(from / size, size, Sort.by("fullPath", "id"));
        Page<ForgeRepositoryEntity> found = switch (wanted) {
            case ALL -> repositories.findByConnectionIdAndLastSeenBy(connectionId, discoveryId, page);
            case NEW -> repositories.findByConnectionIdAndFirstSeenBy(connectionId, discoveryId, page);
            case CHANGED -> repositories.findByConnectionIdAndChangedBy(connectionId, discoveryId, page);
            case GONE -> repositories.findByConnectionIdAndGoneBy(connectionId, discoveryId, page);
        };
        return new RepositoryPage(found.getContent().stream().map(ForgeDiscoveryService::view).toList(),
                found.getTotalElements(), size, from);
    }

    private ForgeConnectionEntity requireConnection(UUID connectionId) {
        return connections.findById(connectionId).orElseThrow(() -> new NotFoundException("Forge connection not found."));
    }

    private ForgeDiscoveryEntity requireDiscovery(UUID connectionId, long discoveryId) {
        requireConnection(connectionId);
        return discoveries.findByIdAndConnectionId(discoveryId, connectionId)
                .orElseThrow(() -> new NotFoundException("Forge discovery " + discoveryId + " not found."));
    }

    private static ForgeDiscoveryConflict inProgress(ForgeDiscoveryEntity running) {
        return new ForgeDiscoveryConflict(ForgeDiscoveryConflict.Cause.IN_PROGRESS, "A discovery of this connection is "
                + "already " + running.getState() + " (discovery " + running.getId() + "): it is the one to follow.",
                Map.of("discoveryId", running.getId()));
    }

    static ForgeDiscoveryView view(ForgeDiscoveryEntity run) {
        return new ForgeDiscoveryView(run.getId(), run.getConnectionId(), DiscoveryState.ofStored(run.getState()),
                DiscoveryReason.ofStored(run.getReason()).orElse(null), run.getDetail(), run.getRequestedAt(),
                run.getRequestedBy(), run.getAttempts(), run.getStartedAt(), run.getFinishedAt(), run.getNamespacesSeen(),
                run.getRepositoriesSeen(), run.getRepositoriesSkipped(), run.getRequestsMade(),
                run.getRateLimitWaitSeconds(), run.getRateLimitResetAt(), run.getNewCount(), run.getChangedCount(),
                run.getGoneCount(), UnreadableNamespace.decode(run.getUnreadableNamespaces()));
    }

    static ForgeRepositoryView view(ForgeRepositoryEntity row) {
        return new ForgeRepositoryView(row.getId(), row.getConnectionId(), row.getForgeId(), row.getFullPath(),
                row.getNamespacePath(), row.getPersonal(), row.getName(), row.getDefaultBranch(), row.getArchived(),
                row.getFork(), row.getVisibility(), row.getLastActivityAt(), row.getLanguage(), row.getSizeBytes(),
                row.getHttpUrl(), row.getSshUrl(), row.getWebUrl(), row.getFirstSeenBy(), row.getFirstSeenAt(),
                row.getLastSeenBy(), row.getLastSeenAt(), row.getChangedBy(), row.getChangeSummary(), row.getGoneBy(),
                row.getGoneAt());
    }
}

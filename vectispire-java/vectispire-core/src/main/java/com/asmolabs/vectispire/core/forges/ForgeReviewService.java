package com.asmolabs.vectispire.core.forges;

import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.net.PinnedCa;
import com.asmolabs.vectispire.common.domain.net.UnsafeUrlException;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.checklists.ChangeReviewDemand;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.forges.internal.ForgeClient;
import com.asmolabs.vectispire.core.forges.internal.ForgeTargets;
import com.asmolabs.vectispire.core.forges.internal.ReviewBounds;
import com.asmolabs.vectispire.core.forges.internal.ReviewReader;
import com.asmolabs.vectispire.core.forges.internal.ReviewState;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeReviewReadingEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeReviewReadingRepository;
import com.asmolabs.vectispire.core.forges.persistence.SnapshotUrls;
import com.asmolabs.vectispire.core.outbound.OutboundJson;
import com.asmolabs.vectispire.core.outbound.OutboundPager;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

/**
 * Reads, through each repository's forge connection, how changes reach the branches the checklists' {@code
 * change_review} lines ask about, and keeps what it read (decision 0037, lot G3). Called by the hourly maintenance
 * turn and by nothing else — never on a request: a reading is pages of merge requests and a request per change.
 *
 * <p><b>Which repositories.</b> Those the lines ask about ({@link ChangeReviewDemand}), for their branch, as far
 * back as the widest window bound to them; a reading of a repository no line asks about any more is deleted. Each is
 * read again once its reading is older than {@link ReviewBounds#refresh}, or narrower than the window now asked.
 *
 * <p><b>Which forge.</b> The connection that imported the target (its provenance link), and otherwise one whose
 * snapshot lists a repository with the target's URL identity ({@link RepositoryUrl#identity}, the rule the
 * repository form and the import apply) — by the forge's id, which a rename keeps. Neither: the reading says
 * {@code unlinked}, and the line why.
 *
 * <p><b>One instance reads each.</b> Every instance runs the maintenance turn; a reading is claimed by a conditional
 * update first ({@link ForgeReviewReadingRepository#claim}), and only the instance that changed the row calls the
 * forge. The row is created beforehand if it does not exist, and an insert refused for any reason — another
 * instance's row, a lock, a dropped connection — is not read as a claim lost: the claim that follows asks the
 * committed row.
 *
 * <p><b>No transaction around a forge.</b> The calls go out between the claim's commit and the write's, each its
 * own; a forge that keeps a thread for a minute holds no row lock.
 *
 * <p><b>A reading that did not happen leaves the previous one.</b> A rate limit longer than a minute, the reading's
 * deadline, a forge that does not answer: the claim is let go and the stored reading stands until it is stale, when
 * the line says so. A refusal is a reading — the forge said no — and is written as one.
 */
@Service
public class ForgeReviewService {

    private static final Logger log = LoggerFactory.getLogger(ForgeReviewService.class);

    private static final int BATCH = 1_000;

    private static final String UNLINKED = "no forge connection imported this repository, and no repository a "
            + "discovery listed has its URL: import it from a forge connection, or run a discovery that lists it";

    private final ChangeReviewDemand demand;
    private final ForgeReviewReadingRepository readings;
    private final ForgeImportLinkRepository links;
    private final ForgeRepositoryRepository snapshot;
    private final ForgeConnectionRepository connections;
    private final TargetCatalog targets;
    private final EncryptionService encryption;
    private final OutboundJson outbound;
    private final Map<ForgeKind, ReviewReader> readers = new EnumMap<>(ForgeKind.class);
    private final ReviewBounds bounds;
    private final Clock clock;

    public ForgeReviewService(
            ChangeReviewDemand demand,
            ForgeReviewReadingRepository readings,
            ForgeImportLinkRepository links,
            ForgeRepositoryRepository snapshot,
            ForgeConnectionRepository connections,
            TargetCatalog targets,
            EncryptionService encryption,
            OutboundJson outbound,
            List<ReviewReader> readers,
            ReviewBounds bounds,
            Clock clock) {
        this.demand = demand;
        this.readings = readings;
        this.links = links;
        this.snapshot = snapshot;
        this.connections = connections;
        this.targets = targets;
        this.encryption = encryption;
        this.outbound = outbound;
        readers.forEach(reader -> this.readers.put(reader.kind(), reader));
        this.bounds = bounds;
        this.clock = clock;
    }

    /** Where a target's forge project is: the connection and the forge's own id. */
    record Link(UUID connectionId, String forgeId) {}

    /**
     * One turn: the readings no line asks for deleted, then every due reading read, up to the turn's bounds.
     *
     * @return how many readings were written
     */
    public int readDue() {
        Instant start = clock.instant();
        Instant turnEnds = start.plus(bounds.turnDuration());
        List<ChangeReviewDemand.Wanted> wanted = demand.wanted();
        sweep(wanted);
        if (wanted.isEmpty()) {
            return 0;
        }
        // Only once a reading is due: matching by URL walks every snapshot, and most turns read nothing.
        Map<Long, Link> linked = null;
        int written = 0;
        for (ChangeReviewDemand.Wanted want : wanted) {
            Instant now = clock.instant();
            if (written >= bounds.maxReadings() || !now.isBefore(turnEnds)) {
                log.info("Change-review readings: the turn's bound was reached after {} readings; the rest at the next.",
                        written);
                break;
            }
            Optional<ForgeReviewReadingEntity> claimed = claim(want, now);
            if (claimed.isEmpty()) {
                continue;
            }
            if (linked == null) {
                linked = links(wanted.stream().map(ChangeReviewDemand.Wanted::repositoryId).distinct().toList());
            }
            if (read(claimed.get(), want, Optional.ofNullable(linked.get(want.repositoryId())), turnEnds)) {
                written++;
            }
        }
        return written;
    }

    // ------------------------------------------------------------------ which rows

    /** Deletes the readings of the repositories no line asks about — unbound, moved out of the project, or deleted. */
    private void sweep(List<ChangeReviewDemand.Wanted> wanted) {
        Set<Long> asked = new HashSet<>();
        wanted.forEach(want -> asked.add(want.repositoryId()));
        List<Long> unasked = readings.repositoriesRead().stream().filter(id -> !asked.contains(id)).toList();
        for (int from = 0; from < unasked.size(); from += BATCH) {
            readings.deleteByRepositories(unasked.subList(from, Math.min(from + BATCH, unasked.size())));
        }
    }

    /** The link of each target: its provenance first, then the snapshots' URLs, only for the targets left. */
    private Map<Long, Link> links(List<Long> repositoryIds) {
        Map<Long, Link> linked = new HashMap<>();
        for (int from = 0; from < repositoryIds.size(); from += BATCH) {
            for (ForgeImportLinkEntity link : links.findByRepositoryIdIn(
                    repositoryIds.subList(from, Math.min(from + BATCH, repositoryIds.size())))) {
                linked.put(link.getRepositoryId(), new Link(link.getConnectionId(), link.getForgeId()));
            }
        }
        List<Long> left = repositoryIds.stream().filter(id -> !linked.containsKey(id)).toList();
        if (left.isEmpty()) {
            return linked;
        }
        // By identity, each snapshot row under the identities of both its clone URLs; the lowest connection id
        // first, so that two connections listing one repository always give the same answer.
        Map<String, Link> byIdentity = new HashMap<>();
        snapshot.currentUrls().stream()
                .sorted(Comparator.comparing((SnapshotUrls row) -> row.connectionId().toString())
                        .thenComparing(SnapshotUrls::forgeId))
                .forEach(row -> {
                    Link link = new Link(row.connectionId(), row.forgeId());
                    RepositoryUrl.identity(row.httpUrl()).ifPresent(identity -> byIdentity.putIfAbsent(identity, link));
                    RepositoryUrl.identity(row.sshUrl()).ifPresent(identity -> byIdentity.putIfAbsent(identity, link));
                });
        for (int from = 0; from < left.size(); from += BATCH) {
            for (RepositoryView repository : targets.repositories(left.subList(from, Math.min(from + BATCH, left.size())))) {
                RepositoryUrl.identity(repository.url()).map(byIdentity::get)
                        .ifPresent(link -> linked.put(repository.id(), link));
            }
        }
        return linked;
    }

    /** The row, created if it is not there, and claimed if it is due and free; empty when another instance has it. */
    private Optional<ForgeReviewReadingEntity> claim(ChangeReviewDemand.Wanted want, Instant now) {
        String branch = want.branch().orElse(ForgeReviewReadingEntity.DEFAULT_BRANCH);
        Optional<ForgeReviewReadingEntity> row = readings.findByRepositoryIdAndWantedBranch(want.repositoryId(), branch);
        if (row.isEmpty()) {
            ForgeReviewReadingEntity created = new ForgeReviewReadingEntity();
            created.setRepositoryId(want.repositoryId());
            created.setWantedBranch(branch);
            created.setState(ReviewState.PENDING.wireName());
            created.setWindowDays(want.windowDays());
            try {
                readings.saveAndFlush(created);
            } catch (DataAccessException refused) {
                // Another instance's row, most likely — or a lock, or a connection lost. Not a claim lost: the
                // committed row is asked below.
                log.debug("Change-review reading of repository {} not created here: {}", want.repositoryId(),
                        refused.getMessage());
            }
            row = readings.findByRepositoryIdAndWantedBranch(want.repositoryId(), branch);
            if (row.isEmpty()) {
                return Optional.empty();
            }
        }
        if (readings.claim(row.get().getId(), now, now.plus(bounds.claim()), now.minus(bounds.refresh()),
                want.windowDays()) != 1) {
            return Optional.empty();
        }
        return readings.findById(row.get().getId());
    }

    // ------------------------------------------------------------------ one reading

    /** Reads one claimed row and writes what was read; false when nothing was, and the claim was let go. */
    private boolean read(ForgeReviewReadingEntity row, ChangeReviewDemand.Wanted want, Optional<Link> link,
            Instant turnEnds) {
        Instant now = clock.instant();
        if (link.isEmpty()) {
            write(row, want, now, Optional.empty(), ReviewState.UNLINKED, UNLINKED, null);
            return true;
        }
        Optional<ForgeConnectionEntity> connection = connections.findById(link.get().connectionId());
        if (connection.isEmpty()) {
            write(row, want, now, Optional.empty(), ReviewState.UNLINKED, UNLINKED, null);
            return true;
        }
        ForgeKind kind = ForgeKind.parse(connection.get().getKind());
        ReviewReader reader = readers.get(kind);
        if (reader == null) {
            write(row, want, now, link, ReviewState.UNREADABLE, "this version does not read change reviews from "
                    + kind.wireName() + " connections", null);
            return true;
        }
        Optional<PinnedCa> ca;
        try {
            ca = ForgeTargets.storedCa(connection.get(), now);
        } catch (InvalidInputException unusable) {
            write(row, want, now, link, ReviewState.UNREADABLE, unusable.getMessage() + " Replace the CA on the connection.",
                    null);
            return true;
        }
        SecretCipher.Decrypted sealed = encryption.inspect(connection.get().getToken(),
                SecretCipher.forgeConnectionContext(link.get().connectionId().toString()));
        if (sealed.state() == SecretCipher.SecretState.UNREADABLE) {
            write(row, want, now, link, ReviewState.UNREADABLE, "the connection's token can no longer be decrypted by "
                    + "any configured key: replace it on the connection", null);
            return true;
        }
        ForgeClient.Target target = ForgeTargets.of(connection.get(), connection.get().isInternalNetwork(), ca);
        Instant deadline = now.plus(bounds.readingDuration());
        OutboundPager pager = outbound.pager(new OutboundPager.Settings(target.address().apiRoot(), target.policy(),
                target.address().edition().label() + " at " + target.address().baseUrl(),
                reader.credential(sealed.plainText()), target.trust(), deadline.isBefore(turnEnds) ? deadline : turnEnds,
                bounds.maxRateLimitWait(), OutboundJson.TIMEOUT, null), clock, OutboundPager.Sleeper.REAL);
        ReviewReader.Reading reading;
        try {
            reading = reader.read(pager, target.address().apiRoot(), link.get().forgeId(), want.branch(),
                    now.minus(Duration.ofDays(want.windowDays())), want.windowDays(), bounds.maxChanges());
        } catch (UnsafeUrlException | OutboundPager.CrossOriginPageException refused) {
            write(row, want, now, link, ReviewState.UNREADABLE, refused.getMessage(), null);
            return true;
        } catch (OutboundPager.RateLimitedException | OutboundPager.DeadlineReachedException
                | OutboundJson.OutboundFailureException transientFailure) {
            log.warn("Change-review reading of repository {} did not happen ({}); the previous one stands.",
                    want.repositoryId(), transientFailure.getMessage());
            readings.release(row.getId());
            return false;
        } catch (RuntimeException unforeseen) {
            log.error("Change-review reading of repository {} failed unexpectedly: {}", want.repositoryId(),
                    unforeseen.getMessage(), unforeseen);
            readings.release(row.getId());
            return false;
        }
        switch (reading) {
            case ReviewReader.Reading.Read read -> write(row, want, now, link, ReviewState.READ, null, read.evidence());
            case ReviewReader.Reading.Unreadable unreadable -> write(row, want, now, link, ReviewState.UNREADABLE,
                    unreadable.why(), null);
        }
        return true;
    }

    private void write(ForgeReviewReadingEntity row, ChangeReviewDemand.Wanted want, Instant at, Optional<Link> link,
            ReviewState state, String reason, ChangeReviewEvidence evidence) {
        row.setState(state.wireName());
        row.setConnectionId(link.map(Link::connectionId).orElse(null));
        row.setForgeId(link.map(Link::forgeId).orElse(null));
        row.setWindowDays(want.windowDays());
        row.setReadAt(at);
        row.setReason(reason == null ? null : BoundedText.clip(reason, 1000));
        String json = evidence == null ? null : evidence.json();
        row.setEvidence(json);
        row.setEvidenceSha256(json == null ? null : Digests.sha256Hex(json));
        row.setClaimedUntil(null);
        readings.saveAndFlush(row);
    }
}

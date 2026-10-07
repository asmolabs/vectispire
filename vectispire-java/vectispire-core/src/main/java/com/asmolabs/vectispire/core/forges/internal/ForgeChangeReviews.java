package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Look;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.core.checklists.ChangeReviews;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeReviewReadingEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeReviewReadingRepository;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * The checklists' port onto the stored readings (decision 0037, lot G3): what each repository's newest reading
 * said, as the rule reads it, and nothing for a repository never read — a reading claimed and not yet written
 * included, which the rule reads as "no reading yet", never as a pass.
 *
 * <p><b>A suspended connection's readings are not handed over</b> (decision 0040 §2). When the row names a connection
 * whose forge's integration is disabled, the rule is told so, whatever the row says — a reading that passed before
 * the switch would otherwise go on passing, on a forge the installation no longer talks to, until it went stale. The
 * registry is asked here, at every read, rather than written into the rows when a governor switches: re-enabling
 * then resumes every line at once with nothing to rewrite, and a measurement frozen by a sign-off keeps what it said.
 */
@Component
class ForgeChangeReviews implements ChangeReviews {

    private static final int BATCH = 1_000;

    private final ForgeReviewReadingRepository readings;
    private final ForgeConnectionRepository connections;
    private final ForgeIntegrations integrations;

    ForgeChangeReviews(
            ForgeReviewReadingRepository readings, ForgeConnectionRepository connections, ForgeIntegrations integrations) {
        this.readings = readings;
        this.connections = connections;
        this.integrations = integrations;
    }

    @Override
    public Map<Long, MeasurementFacts.ReviewFacts> recorded(Collection<Long> repositoryIds, Optional<String> branch) {
        List<Long> ids = repositoryIds.stream().distinct().toList();
        Map<Long, MeasurementFacts.ReviewFacts> recorded = new HashMap<>();
        Map<UUID, ForgeKind> suspended = suspendedConnections();
        for (int from = 0; from < ids.size(); from += BATCH) {
            for (ForgeReviewReadingEntity row : readings.findByWantedBranchAndRepositoryIdIn(
                    branch.orElse(ForgeReviewReadingEntity.DEFAULT_BRANCH), ids.subList(from, Math.min(from + BATCH, ids.size())))) {
                ForgeKind off = row.getConnectionId() == null ? null : suspended.get(row.getConnectionId());
                Optional<Look> newest = Optional.ofNullable(row.getReadAt()).map(at -> new Look(
                        MeasurementFacts.Source.FORGE_REVIEW, row.getId(), at, Optional.ofNullable(row.getEvidenceSha256())));
                if (off != null) {
                    recorded.put(row.getRepositoryId(),
                            new MeasurementFacts.ReviewSuspended(newest, ForgeIntegrations.suspension(off)));
                    continue;
                }
                if (newest.isEmpty()) {
                    continue;
                }
                Look look = newest.get();
                Optional<ReviewState> state = ReviewState.ofStored(row.getState());
                if (state.isEmpty() || state.get() == ReviewState.PENDING) {
                    continue;
                }
                recorded.put(row.getRepositoryId(), switch (state.get()) {
                    case READ -> new MeasurementFacts.ReviewRead(look, ChangeReviewEvidence.read(row.getEvidence()));
                    case UNREADABLE -> new MeasurementFacts.ReviewUnreadable(look, row.getReason());
                    case UNLINKED -> new MeasurementFacts.ReviewUnlinked(look, row.getReason());
                    case PENDING -> throw new IllegalStateException("Left out above.");
                });
            }
        }
        return recorded;
    }

    /** The connections whose forge is switched off, by id; none asked of the table while every forge is on. */
    private Map<UUID, ForgeKind> suspendedConnections() {
        Set<ForgeKind> disabled = integrations.disabled();
        if (disabled.isEmpty()) {
            return Map.of();
        }
        // The connections are an administrator's handful, not data-sized: read whole rather than by a list of ids.
        Map<UUID, ForgeKind> suspended = new HashMap<>();
        for (ForgeConnectionEntity connection : connections.findAll()) {
            ForgeKind kind = ForgeKind.parse(connection.getKind());
            if (disabled.contains(kind)) {
                suspended.put(connection.getId(), kind);
            }
        }
        return suspended;
    }
}

package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.checklists.ChangeReviewEvidence;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts;
import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts.Look;
import com.asmolabs.vectispire.core.checklists.ChangeReviews;
import com.asmolabs.vectispire.core.forges.persistence.ForgeReviewReadingEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeReviewReadingRepository;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * The checklists' port onto the stored readings (decision 0037, lot G3): what each repository's newest reading
 * said, as the rule reads it, and nothing for a repository never read — a reading claimed and not yet written
 * included, which the rule reads as "no reading yet", never as a pass.
 */
@Component
class ForgeChangeReviews implements ChangeReviews {

    private static final int BATCH = 1_000;

    private final ForgeReviewReadingRepository readings;

    ForgeChangeReviews(ForgeReviewReadingRepository readings) {
        this.readings = readings;
    }

    @Override
    public Map<Long, MeasurementFacts.ReviewFacts> recorded(Collection<Long> repositoryIds, Optional<String> branch) {
        List<Long> ids = repositoryIds.stream().distinct().toList();
        Map<Long, MeasurementFacts.ReviewFacts> recorded = new HashMap<>();
        for (int from = 0; from < ids.size(); from += BATCH) {
            for (ForgeReviewReadingEntity row : readings.findByWantedBranchAndRepositoryIdIn(
                    branch.orElse(ForgeReviewReadingEntity.DEFAULT_BRANCH), ids.subList(from, Math.min(from + BATCH, ids.size())))) {
                if (row.getReadAt() == null) {
                    continue;
                }
                Look look = new Look(MeasurementFacts.Source.FORGE_REVIEW, row.getId(), row.getReadAt(),
                        Optional.ofNullable(row.getEvidenceSha256()));
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
}

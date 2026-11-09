package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.checklists.MeasurementFacts;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

/**
 * What the forges recorded of how changes reach a repository's branch — the evidence of the {@code change_review}
 * rule (decision 0037, lot G3) — declared here and implemented by {@code forges}, which sits above this module: it
 * reads which lines ask ({@link ChangeReviewDemand}) and keeps the readings, and this module only reads them. The
 * reverse dependency would have put a forge's token one call away from a checklist route.
 *
 * <p><b>Read, never measured, here.</b> A reading calls the forge — pages of merge requests, one request each
 * for their approvals — which is the maintenance task's, never a request's: a checklist read on screen asks only
 * what was stored.
 */
public interface ChangeReviews {

    /**
     * The newest reading of each repository for the branch; a repository missing from the answer was never read.
     *
     * @param branch the rule's branch; empty for the default branch the forge names
     */
    Map<Long, MeasurementFacts.ReviewFacts> recorded(Collection<Long> repositoryIds, Optional<String> branch);
}

package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.targets.TargetPurge;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResults;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.util.List;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The model reviews run on a purged target's scans, before the scans.
 *
 * <p>Here because {@code OwaspReviewService} is what writes them. Synchronous and in the deleting
 * transaction, like every {@link TargetPurge} listener.
 */
@Component
class AiReviewPurge {

    private final Scans scans;
    private final AiReviewResults reviews;

    AiReviewPurge(Scans scans, AiReviewResults reviews) {
        this.scans = scans;
        this.reviews = reviews;
    }

    @EventListener
    @Order(TargetPurge.Phase.SCAN_CHILDREN)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(TargetPurge purge) {
        List<Long> scanIds = scans.findIdsPurgedBy(purge);
        if (!scanIds.isEmpty()) {
            reviews.deleteByScanIdIn(scanIds);
        }
    }
}

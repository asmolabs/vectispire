package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The model reviews a stopped process left running, settled as failed.
 *
 * <p>A review is recorded {@code running} before the model is asked and settled after, in two
 * transactions with the call between them. A restart in between leaves the row saying {@code
 * running} for ever; the screen already reads it as failed once its deadline has passed, and this
 * writes it so, which is what the PDF route and any later reader see. Tolerates several instances:
 * the update only touches rows still running past their deadline. Never throws; a failure waits for
 * the next turn.
 */
@Component
@Order(MaintenanceTask.Sequence.ABANDONED_REVIEWS)
public class AbandonedReviewsTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(AbandonedReviewsTask.class);

    private final OwaspReviewService reviews;

    public AbandonedReviewsTask(OwaspReviewService reviews) {
        this.reviews = reviews;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        try {
            int settled = reviews.settleAbandoned();
            if (settled > 0) {
                log.info("Maintenance: {} model review(s) abandoned by a stopped process settled as failed.", settled);
            }
        } catch (RuntimeException failed) {
            log.warn("Abandoned model reviews not settled: {}", failed.getMessage());
        }
    }
}

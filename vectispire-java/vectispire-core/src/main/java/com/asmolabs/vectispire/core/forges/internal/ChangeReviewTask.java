package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.core.forges.ForgeReviewService;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The forges read again how changes reach the branches the checklists' {@code change_review} lines ask about
 * (decision 0037, lot G3).
 *
 * <p><b>The only caller of the reading.</b> Without this turn every change-review line says "no reading yet" for as
 * long as the installation lives, and a reading taken once goes stale after the rule's age. Hourly, and each reading
 * is due only every few hours ({@code ReviewBounds.refresh}): most turns cost a query and a few conditional updates.
 * Every instance runs it; each reading is claimed first, so one instance calls the forge.
 *
 * <p>After the threat-intelligence feeds and before the orphaned rows: it calls forges for up to the turn's bound,
 * and only the orphaned rows wait behind it. Never throws.
 */
@Component
@Order(MaintenanceTask.Sequence.CHANGE_REVIEWS)
public class ChangeReviewTask implements MaintenanceTask {

    private static final Logger log = LoggerFactory.getLogger(ChangeReviewTask.class);

    private final ForgeReviewService reviews;

    public ChangeReviewTask(ForgeReviewService reviews) {
        this.reviews = reviews;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        try {
            int read = reviews.readDue();
            if (read > 0) {
                log.info("Maintenance: {} change-review reading(s) of forge projects written.", read);
            }
        } catch (RuntimeException failed) {
            log.warn("Change-review readings skipped: {}", failed.getMessage());
        }
    }
}

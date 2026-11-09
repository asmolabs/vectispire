package com.asmolabs.vectispire.core.posture.internal;

import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.posture.PostureDigestService;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The weekly posture report, offered every hour.
 *
 * <p><b>This task is the only thing that makes the feature exist.</b> A weekly report needs no queue —
 * it is derived from the database, so a failed send is simply recomputed next turn — which is exactly
 * the shape {@code expireStale} had when its javadoc claimed the tick ran it and nothing did.
 *
 * <p>Hourly for a weekly job: the digest decides for itself whether one has gone out since Monday, so
 * the turn only has to be more frequent than the period.
 */
@Component
@Order(MaintenanceTask.Sequence.WEEKLY_DIGEST)
public class WeeklyDigestTask implements MaintenanceTask {

    private final PostureDigestService digest;

    public WeeklyDigestTask(PostureDigestService digest) {
        this.digest = digest;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        digest.runOnce();
    }
}

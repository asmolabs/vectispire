package com.asmolabs.vectispire.core.reportplugins.internal;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunReason;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunState;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

/**
 * The report runs' queue: the claim, and the runs whose executor stopped answering (decision 0035 §2).
 *
 * <p><b>The scan queue's pattern, not a mechanism of its own</b>: the waiting runs read oldest first, each taken by
 * a conditional update naming the state it expects, so that of two executors — two instances of the control plane
 * — racing on one run exactly one takes it; no row lock is held, so no claim waits on another's.
 *
 * <p><b>A lease, renewed, and no retry.</b> A claim holds its run for {@link #LEASE}: the longest timeout a manifest
 * may declare, the verifier's two minutes before it, and the ten minutes decision 0035 gives a lost executor. <b>The
 * executor renews it while the run is alive</b> ({@link #renew}, every third of the lease, {@code ReportWorker}):
 * the lease was fixed at first, and a run whose pull or signature check was slow outlived it, was failed as lost by
 * the next turn while it still ran, and had what it then produced dropped — a slow registry read as a dead
 * executor. Renewed, a run past its lease was left by an executor that stopped renewing — died, at a restart or for
 * good. It is <b>failed</b>, {@code executor_lost}, not requeued: a report is somebody's request, and running it
 * again later would describe another instant than the one they asked for. They ask again. Every instance with an
 * executor looks for such runs at each turn, which covers a start-up as well as a sibling gone.
 *
 * <p>{@code vectispire.reports.lease} shortens the lease for the suite that waits for one to lapse; the default is
 * the decision's, and an operator has no reason to move it.
 */
@Component
public class ReportQueue {

    /** {@link ReportPluginManifest#MAX_TIMEOUT_SECONDS}, the verifier's two minutes, and ten minutes. */
    static final Duration LEASE = Duration.ofSeconds(ReportPluginManifest.MAX_TIMEOUT_SECONDS)
            .plus(Duration.ofMinutes(2))
            .plus(Duration.ofMinutes(10));

    /** How many waiting runs a claim reads before it gives up for this turn: a few lost races, no more. */
    static final int CANDIDATES = 8;

    private final ReportRunRepository runs;
    private final AuditLogService audit;
    private final Clock clock;
    private final Duration lease;

    public ReportQueue(ReportRunRepository runs, AuditLogService audit, Clock clock,
            @Value("${vectispire.reports.lease:#{null}}") Duration lease) {
        this.runs = runs;
        this.audit = audit;
        this.clock = clock;
        this.lease = lease == null ? LEASE : lease;
    }

    /** How long a claim, or a renewal, holds a run. */
    public Duration lease() {
        return lease;
    }

    /** Takes the oldest waiting run for {@code owner}: its id, or empty when none was left to take. */
    public Optional<Long> claim(String owner) {
        Instant now = clock.instant();
        for (Long id : runs.waiting(ReportRunState.PENDING.wireName(), PageRequest.of(0, CANDIDATES))) {
            if (runs.take(id, ReportRunState.PENDING.wireName(), ReportRunState.RUNNING.wireName(), owner, now,
                    now.plus(lease)) == 1) {
                return Optional.of(id);
            }
        }
        return Optional.empty();
    }

    /**
     * Extends {@code owner}'s lease on run {@code runId} by a whole lease from now: false when the run is no longer
     * its own — ended, failed as lost, or never taken by it.
     */
    public boolean renew(long runId, String owner) {
        return runs.renew(runId, ReportRunState.RUNNING.wireName(), owner, clock.instant().plus(lease)) == 1;
    }

    /**
     * Fails every running run whose lease lapsed, {@code executor_lost}, each audited {@code REPORT_FAILED} in its
     * requester's name: the ids it failed.
     */
    public List<Long> failLapsed() {
        Instant now = clock.instant();
        List<Long> failed = new ArrayList<>();
        for (Long id : runs.lapsed(ReportRunState.RUNNING.wireName(), now)) {
            int ended = runs.failLapsed(id, ReportRunState.RUNNING.wireName(), ReportRunState.FAILED.wireName(),
                    ReportRunReason.EXECUTOR_LOST.wireName(), "The executor that claimed this run stopped answering "
                            + "before it ended; nothing it produced is kept. Request the report again.", now);
            if (ended == 1) {
                failed.add(id);
                runs.findById(id).ifPresent(run -> audit.record(new RequestActor(run.getRequestedBy(), null, null).entry(
                        AuditOperation.REPORT_FAILED, String.valueOf(id), "Report run " + id + " of report plugin \""
                                + run.getPluginId() + "\" for project " + run.getProjectId() + " failed, executor_lost: "
                                + "its executor stopped answering.")));
            }
        }
        return failed;
    }
}

package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Clock;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Putting a scan in the queue on somebody's request.
 *
 * <p><b>Queueing, not running.</b> The call returns at once; a worker — built-in or remote —
 * will claim the row. Running it here would keep the caller waiting minutes behind an HTTP
 * request, and a page reload would start the scan again.
 *
 * <p>Its own service rather than a method on each controller, because the scheduler queues the
 * same rows: three places building a scan row is three places that can forget the required
 * label, and targeting would then be true "except for one of the three ways to start a scan".
 */
@Service
public class ScanTriggerService {

    private final Scans scans;
    private final Clock clock;

    public ScanTriggerService(Scans scans, Clock clock) {
        this.scans = scans;
        this.clock = clock;
    }

    /** Raised when a scan of the same target is already waiting. */
    public static class AlreadyQueuedException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        AlreadyQueuedException(String message) {
            super(message);
        }
    }

    @Transactional
    public ScanEntity trigger(RepositoryEntity repository) {
        refuseIfQueued(scans.countByStatusAndRepoId(ScanStatus.PENDING.wireName(), repository.getId()));

        ScanEntity scan = pending();
        scan.setRepoId(repository.getId());
        scan.setBranch(repository.getBranch());
        scan.setSubPath(repository.getSubPath());
        // Copied at queue time: this scan keeps the requirement that held when it was asked
        // for, even if the target's label changes afterwards.
        scan.setRequiredAgentLabel(repository.getRequiredAgentLabel());
        return scans.save(scan);
    }

    @Transactional
    public ScanEntity trigger(ContainerEntity container) {
        refuseIfQueued(scans.countByStatusAndContainerId(ScanStatus.PENDING.wireName(), container.getId()));

        ScanEntity scan = pending();
        scan.setContainerId(container.getId());
        // "n/a", the same value the scheduler writes: a manual scan and a scheduled one must be
        // indistinguishable downstream.
        scan.setBranch("n/a");
        scan.setRequiredAgentLabel(container.getRequiredAgentLabel());
        return scans.save(scan);
    }

    private ScanEntity pending() {
        ScanEntity scan = new ScanEntity();
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(clock.instant());
        return scan;
    }

    /**
     * Refused rather than stacked.
     *
     * <p>Ten clicks on the button would give ten identical scans in a row, nine of them
     * pointless — and the tenth reporting on a tree that has not changed since the first.
     */
    private static void refuseIfQueued(long alreadyQueued) {
        if (alreadyQueued > 0) {
            throw new AlreadyQueuedException("A scan of this target is already queued.");
        }
    }
}

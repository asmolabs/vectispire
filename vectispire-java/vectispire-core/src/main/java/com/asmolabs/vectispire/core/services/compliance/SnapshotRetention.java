package com.asmolabs.vectispire.core.services.compliance;

import com.asmolabs.vectispire.core.repositories.ComplianceSnapshots;
import com.asmolabs.vectispire.core.services.access.SessionCleanupService;
import java.time.Instant;
import org.springframework.stereotype.Component;

/**
 * The monthly compliance captures, purged past the evidence window with the gate's register.
 *
 * <p>The same port as the gate's {@code VerdictRetention}, for the same reason: {@code access} sits
 * below {@code compliance}, and the purge read {@code ComplianceSnapshots} from inside it.
 */
@Component
class SnapshotRetention implements SessionCleanupService.EvidencePurge {

    private final ComplianceSnapshots snapshots;

    SnapshotRetention(ComplianceSnapshots snapshots) {
        this.snapshots = snapshots;
    }

    @Override
    public int deleteBefore(Instant cutoff) {
        return snapshots.deleteBefore(cutoff);
    }

    @Override
    public String label() {
        return "Compliance snapshot";
    }
}

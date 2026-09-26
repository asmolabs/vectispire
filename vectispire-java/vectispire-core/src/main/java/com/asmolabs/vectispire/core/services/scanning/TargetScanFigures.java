package com.asmolabs.vectispire.core.services.scanning;

import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.LatestScanRow;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.targets.ContainerView;
import com.asmolabs.vectispire.core.services.targets.RepositoryView;
import com.asmolabs.vectispire.core.services.targets.TargetScans;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** {@code targets}' {@link TargetScans}: the same grouped queries its listings ran, and the same trigger. */
@Service
public class TargetScanFigures implements TargetScans {

    private final Scans scans;
    private final ScanTriggerService trigger;

    public TargetScanFigures(Scans scans, ScanTriggerService trigger) {
        this.scans = scans;
        this.trigger = trigger;
    }

    @Override
    @Transactional(readOnly = true)
    public Map<Long, LatestScan> latestPerRepository() {
        return byTarget(scans.findLatestPerRepository());
    }

    @Override
    @Transactional(readOnly = true)
    public Map<Long, LatestScan> latestPerContainer() {
        return byTarget(scans.findLatestPerContainer());
    }

    @Override
    public Queued queue(RepositoryView repository) {
        return queued(trigger.trigger(repository));
    }

    @Override
    public Queued queue(ContainerView container) {
        return queued(trigger.trigger(container));
    }

    private static Map<Long, LatestScan> byTarget(List<LatestScanRow> rows) {
        Map<Long, LatestScan> latest = new HashMap<>();
        for (LatestScanRow row : rows) {
            latest.put(row.targetId(), new LatestScan(row.scanId(), row.status(), row.createdAt(), row.error()));
        }
        return latest;
    }

    private static Queued queued(ScanEntity scan) {
        return new Queued(scan.getId(), scan.getStatus());
    }
}

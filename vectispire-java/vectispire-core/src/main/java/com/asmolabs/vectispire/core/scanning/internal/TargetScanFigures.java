package com.asmolabs.vectispire.core.scanning.internal;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanTriggerService;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.scanning.persistence.queries.LatestScanRow;
import com.asmolabs.vectispire.core.targets.ContainerView;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetScans;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** {@code targets}' {@link TargetScans}: the same grouped queries its listings ran, and the same trigger. */
@Service
public class TargetScanFigures implements TargetScans {

    private final ScanRepository scans;
    private final ScanTriggerService trigger;
    private final ScanCatalog catalog;

    public TargetScanFigures(ScanRepository scans, ScanTriggerService trigger, ScanCatalog catalog) {
        this.scans = scans;
        this.trigger = trigger;
        this.catalog = catalog;
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
    public Map<Long, Set<Language>> detectedLanguages(Collection<Long> repositoryIds) {
        return catalog.newestDetectedLanguages(repositoryIds);
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

package com.asmolabs.vectispire.core.services.issues;

import com.asmolabs.vectispire.core.scanning.ScanIngestor;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * {@code scanning}'s {@link ScanIngestor.Backlog}: a completed scan's findings folded into the issue
 * history, and the delta announced before the scan's transaction commits.
 */
@Service
public class IssueBacklog implements ScanIngestor.Backlog {

    private final IssueSyncService sync;
    private final Optional<ScanDelta.Sink> deltas;

    public IssueBacklog(IssueSyncService sync, Optional<ScanDelta.Sink> deltas) {
        this.sync = sync;
        this.deltas = deltas;
    }

    /** {@code MANDATORY}, like the sync: the issues commit with the scan's findings, or not at all. */
    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public ScanIngestor.Reconciliation reconcile(ScanIngestor.Observation observation) {
        IssueSyncService.SyncResult result = sync.sync(
                observation.scanId(),
                observation.target(),
                observation.findings(),
                observation.scannedTypes(),
                observation.descriptions(),
                done -> deltas.ifPresent(sink -> sink.enqueue(new ScanDelta(
                        observation.scanId(),
                        observation.target(),
                        views(done.newIssues()),
                        views(done.reopenedIssues()),
                        done.resolved()))));
        return new ScanIngestor.Reconciliation(
                result.created(), result.resolved(), result.reopened(), result.stillOpen(), result.issueIds());
    }

    private static List<IssueView> views(List<com.asmolabs.vectispire.core.persistence.IssueEntity> issues) {
        return issues.stream().map(IssueView::of).toList();
    }
}

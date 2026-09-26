package com.asmolabs.vectispire.core.services.issues;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.List;

/**
 * What one scan changed in a target's backlog: the issues it opened, the ones it reopened, how many
 * it resolved.
 *
 * <p>Announced through {@link Sink}, inside the scan's transaction, so that a notification becomes
 * durable at the same instant as the issues it describes — queued one line after the commit, it would
 * be lost by the very crash the outbox exists to cover.
 *
 * @param newIssues the issues themselves, not only the counts: a notification has to say <em>what</em>
 *     appeared, and rebuilding the list afterwards would mean re-deducing "which ones are new"
 */
public record ScanDelta(
        long scanId, ScanTarget target, List<IssueView> newIssues, List<IssueView> reopenedIssues, int resolved) {

    /**
     * Where a delta goes — {@code notifications}' routing, and nothing else so far.
     *
     * <p><b>A port of {@code issues}</b>, since the delta is the backlog's. It was {@code
     * ScanIngestor.NotificationSink}, in {@code scanning}, handed the scan's entity and the sync's
     * result with its issue rows; the delta has been the backlog's to announce since the backlog
     * became a port of the ingestion (decision 0029). Optional: without it, reconciling is exactly
     * what it was.
     */
    public interface Sink {
        /** Queues the delta inside the caller's transaction, or does nothing. */
        void enqueue(ScanDelta delta);
    }
}

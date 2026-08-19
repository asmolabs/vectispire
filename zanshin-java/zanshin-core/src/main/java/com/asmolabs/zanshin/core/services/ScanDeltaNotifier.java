package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.notifications.NotificationPayload.NotifiableIssue;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * The bridge between a reconciliation's outcome and the notification queue.
 *
 * <p>Its own class rather than a method on either side, because it is the only place that knows
 * both: {@link IssueSyncService} must not learn what a webhook is, and {@link
 * NotificationService} must not learn what an issue row looks like.
 */
@Service
public class ScanDeltaNotifier implements ScanIngestor.NotificationSink {

    private final NotificationService notifications;
    private final OutboxService outbox;
    private final TargetNaming names;

    public ScanDeltaNotifier(
            NotificationService notifications, OutboxService outbox, TargetNaming names) {
        this.notifications = notifications;
        this.outbox = outbox;
        this.names = names;
    }

    /**
     * Queues the delta <b>inside the caller's transaction</b>, or does nothing.
     *
     * <p>Nothing is sent here. The message becomes durable with the scan's results and leaves
     * later, through the relay — that is the whole point of the outbox, and queueing it one line
     * after the commit would reintroduce exactly the window it removes.
     */
    @Override
    public void enqueue(ScanEntity scan, IssueSyncService.SyncResult result) {
        notifications
                .buildScanDelta(
                        names.all().of(scan.getRepoId(), scan.getContainerId()),
                        scan.getId(),
                        notifiable(result.newIssues()),
                        notifiable(result.reopenedIssues()),
                        result.resolved())
                .ifPresent(payload -> outbox.enqueue(payload, OutboxService.TYPE_SCAN_DELTA));
    }

    private static List<NotifiableIssue> notifiable(List<IssueEntity> issues) {
        return issues.stream().map(ScanDeltaNotifier::notifiable).toList();
    }

    private static NotifiableIssue notifiable(IssueEntity issue) {
        return new NotifiableIssue(
                issue.getId(),
                issue.getIdentifier(),
                FindingType.fromWireName(issue.getType()).orElse(null),
                Severity.of(issue.getSeverity()),
                issue.getIsKev(),
                issue.getEpssScore(),
                issue.getPackageName(),
                issue.getFilePath(),
                issue.getFixVersions(),
                issue.getLink());
    }
}

package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.notifications.NotificationPayload.NotifiableIssue;
import com.asmolabs.zanshin.common.domain.targets.ImageReference;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Containers;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import java.util.List;
import java.util.Optional;
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
    private final GitRepositories repositories;
    private final Containers containers;

    public ScanDeltaNotifier(
            NotificationService notifications,
            OutboxService outbox,
            GitRepositories repositories,
            Containers containers) {
        this.notifications = notifications;
        this.outbox = outbox;
        this.repositories = repositories;
        this.containers = containers;
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
                        targetName(scan),
                        scan.getId(),
                        notifiable(result.newIssues()),
                        notifiable(result.reopenedIssues()),
                        result.resolved())
                .ifPresent(payload -> outbox.enqueue(payload, OutboxService.TYPE_SCAN_DELTA));
    }

    /**
     * What the alert calls the target.
     *
     * <p>Resolved here and not carried on the scan: the row holds identifiers, and an alert
     * naming "repository 7" would be an alert nobody can act on without opening the interface.
     */
    private String targetName(ScanEntity scan) {
        if (scan.getRepoId() != null) {
            return repositories
                    .findById(scan.getRepoId())
                    .map(repository -> Optional.ofNullable(repository.getName()).orElseGet(repository::getUrl))
                    .orElseGet(() -> "repository " + scan.getRepoId());
        }
        if (scan.getContainerId() != null) {
            return containers
                    .findById(scan.getContainerId())
                    .map(container -> new ImageReference(
                                    container.getRegistry(), container.getImageName(), container.getTag())
                            .displayName())
                    .orElseGet(() -> "image " + scan.getContainerId());
        }
        return "unknown target";
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

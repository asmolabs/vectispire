package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.notifications.NotificationPayload.NotifiableIssue;
import com.asmolabs.zanshin.common.domain.teams.TeamRules;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.persistence.TeamWebhookEntity;
import com.asmolabs.zanshin.core.repositories.TeamTargets;
import com.asmolabs.zanshin.core.repositories.TeamWebhooks;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * The bridge between a reconciliation's outcome and the notification queue.
 *
 * <p>Its own class rather than a method on either side, because it is the only place that knows
 * both: {@link IssueSyncService} must not learn what a webhook is, and {@link
 * NotificationService} must not learn what an issue row looks like.
 *
 * <p><b>And it is where a notification is routed</b>, because it is also the only place that
 * knows which target the delta is about. One copy for the global channel and one per owning team
 * that has its own: with a single global webhook, a deployment that carefully restricted its
 * screens still announced every team's vulnerabilities where everybody reads.
 */
@Service
public class ScanDeltaNotifier implements ScanIngestor.NotificationSink {

    private final NotificationService notifications;
    private final List<NotificationChannel> channels;
    private final OutboxService outbox;
    private final TargetNaming names;
    private final TeamTargets teamTargets;
    private final TeamWebhooks teamWebhooks;

    public ScanDeltaNotifier(
            NotificationService notifications,
            List<NotificationChannel> channels,
            OutboxService outbox,
            TargetNaming names,
            TeamTargets teamTargets,
            TeamWebhooks teamWebhooks) {
        this.notifications = notifications;
        this.channels = channels;
        this.outbox = outbox;
        this.names = names;
        this.teamTargets = teamTargets;
        this.teamWebhooks = teamWebhooks;
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
                .ifPresent(payload -> {
                    // **One row per configured destination.** Delivering three from a single row
                    // makes a partial failure unrepresentable: Teams accepted, the relay retries
                    // because the mail server was down, and the channel receives the message
                    // twice. Per-row is what lets the backoff be about one destination.
                    //
                    // A destination that is not configured is queued nothing, rather than queued
                    // and failed — an outbox full of rows that can never leave is an outbox whose
                    // age says nothing. The global channels keep receiving everything: they are
                    // the security team's feed, and narrowing them would be a silent change to
                    // what an existing deployment is told.
                    channels.stream()
                            .filter(NotificationChannel::isConfigured)
                            .forEach(channel -> outbox.enqueue(payload, channel.type()));

                    // And one webhook copy per owning team that has a channel of its own.
                    for (Long teamId : teamsToTell(scan)) {
                        outbox.enqueue(payload, OutboxService.TYPE_SCAN_DELTA, teamId);
                    }
                });
    }

    /**
     * The teams that own this scan's target <b>and</b> have somewhere to be told.
     *
     * <p>Two queries, inside the caller's transaction, on a set of a few rows. Ownership and
     * channel are asked separately because most teams have the first and not the second: queueing
     * a message for a team with no webhook would create a row whose only future is to be
     * abandoned by the relay.
     */
    private List<Long> teamsToTell(ScanEntity scan) {
        String kind = scan.getContainerId() == null ? TeamRules.KIND_REPOSITORY : TeamRules.KIND_CONTAINER;
        Long targetId = scan.getContainerId() == null ? scan.getRepoId() : scan.getContainerId();
        if (targetId == null) {
            return List.of();
        }

        List<Long> owners = teamTargets.findByTarget(kind, targetId).stream()
                .map(row -> row.getId().teamId())
                .distinct()
                .toList();
        if (owners.isEmpty()) {
            return List.of();
        }
        return teamWebhooks.findByTeamIdIn(owners).stream()
                .map(TeamWebhookEntity::getTeamId)
                .toList();
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

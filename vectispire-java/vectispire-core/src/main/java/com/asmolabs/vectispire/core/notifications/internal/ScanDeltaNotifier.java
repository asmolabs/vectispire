package com.asmolabs.vectispire.core.notifications.internal;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.notifications.NotificationPayload.NotifiableIssue;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.core.access.TeamChannels;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.issues.ScanDelta;
import com.asmolabs.vectispire.core.notifications.NotificationService;
import com.asmolabs.vectispire.core.outbox.NotificationChannel;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * The bridge between a reconciliation's outcome and the notification queue.
 *
 * <p>Its own class rather than a method on either side, because it is the only place that knows
 * both: the backlog must not learn what a webhook is, and {@link NotificationService} must not learn
 * what an issue looks like. It implements {@code issues}' {@link ScanDelta.Sink}, the port through
 * which the backlog announces what a scan changed.
 *
 * <p><b>And it is where a notification is routed</b>, because it is also the only place that
 * knows which target the delta is about. One copy for the global channel and one per owning team
 * that has its own: with a single global webhook, a deployment that carefully restricted its
 * screens still announced every team's vulnerabilities where everybody reads.
 */
@Service
public class ScanDeltaNotifier implements ScanDelta.Sink {

    private final NotificationService notifications;
    private final List<NotificationChannel> channels;
    private final OutboxService outbox;
    private final TargetNaming names;
    private final TeamChannels teams;
    private final TargetCatalog targets;

    public ScanDeltaNotifier(
            NotificationService notifications,
            List<NotificationChannel> channels,
            OutboxService outbox,
            TargetNaming names,
            TeamChannels teams,
            TargetCatalog targets) {
        this.notifications = notifications;
        this.channels = channels;
        this.outbox = outbox;
        this.names = names;
        this.teams = teams;
        this.targets = targets;
    }

    /**
     * Queues the delta <b>inside the caller's transaction</b>, or does nothing.
     *
     * <p>Nothing is sent here. The message becomes durable with the scan's results and leaves
     * later, through the relay — that is the whole point of the outbox, and queueing it one line
     * after the commit would reintroduce exactly the window it removes.
     */
    @Override
    public void enqueue(ScanDelta delta) {
        Long repoId = delta.target() instanceof ScanTarget.Repository repository ? repository.id() : null;
        Long containerId = delta.target() instanceof ScanTarget.Container container ? container.id() : null;
        notifications
                .buildScanDelta(
                        names.all().of(repoId, containerId),
                        delta.scanId(),
                        notifiable(delta.newIssues()),
                        notifiable(delta.reopenedIssues()),
                        delta.resolved())
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
                    for (Long teamId : teamsToTell(repoId, containerId)) {
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
     *
     * <p><b>A team owns a repository through its project too</b> (decision 0023). A team granted
     * a project sees the repositories filed in it; were it told only about the repositories it was
     * granted one by one, it would read findings on screen that its channel was never sent — and
     * nothing would say why. The project is read at the moment of the scan, as visibility reads it.
     */
    private List<Long> teamsToTell(Long repoId, Long containerId) {
        String kind = containerId == null ? TeamRules.KIND_REPOSITORY : TeamRules.KIND_CONTAINER;
        Long targetId = containerId == null ? repoId : containerId;
        if (targetId == null) {
            return List.of();
        }

        List<Long> claims = new ArrayList<>(teams.teamsGranted(kind, targetId));
        if (TeamRules.KIND_REPOSITORY.equals(kind)) {
            targets.repository(targetId)
                    .map(RepositoryView::projectId)
                    .ifPresent(projectId -> claims.addAll(teams.teamsGranted(TeamRules.KIND_PROJECT, projectId)));
        }
        List<Long> owners = claims.stream().distinct().toList();
        if (owners.isEmpty()) {
            return List.of();
        }
        return teams.withChannel(owners);
    }

    private static List<NotifiableIssue> notifiable(List<IssueView> issues) {
        return issues.stream().map(ScanDeltaNotifier::notifiable).toList();
    }

    private static NotifiableIssue notifiable(IssueView issue) {
        return new NotifiableIssue(
                issue.id(),
                issue.identifier(),
                FindingType.fromWireName(issue.type()).orElse(null),
                Severity.of(issue.severity()),
                issue.isKev(),
                issue.epssScore(),
                issue.packageName(),
                issue.filePath(),
                issue.fixVersions(),
                issue.link());
    }
}

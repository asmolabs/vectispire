package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.access.Visibility;
import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.gate.SecurityOverview;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.notifications.PostureDigest;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.common.domain.trends.BacklogTrend;
import com.asmolabs.zanshin.core.repositories.AuditLog;
import com.asmolabs.zanshin.core.repositories.IssueFilters;
import com.asmolabs.zanshin.core.repositories.Issues;
import java.time.Clock;
import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAdjusters;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * The weekly posture report.
 *
 * <h2>Why this needs no outbox, when every other notification does</h2>
 *
 * <p>A scan delta describes a moment: it says what <em>that</em> scan changed, and if the process
 * dies between the commit and the POST the message cannot be rebuilt — hence the outbox row
 * written inside the scan's transaction.
 *
 * <p>A digest is the opposite kind of thing. It is <b>derived from the database as it stands</b>, so
 * a failed send loses nothing: the next hourly tick recomputes it and tries again, and what
 * eventually arrives is a report of the same week with fresher numbers. Giving it an outbox row
 * would add durability to something already durable, and would mean retrying a stale snapshot for
 * twelve attempts when a correct one was one query away.
 *
 * <h2>Once a week, and the log is what remembers</h2>
 *
 * <p>"Has one gone out since Monday" is answered by looking for a {@code POSTURE_DIGEST_SENT} entry
 * in the audit log, not by a timestamp this service keeps. The log is append-only and never purged,
 * which makes it a stronger ledger than a settings row somebody can edit — and it puts the answer
 * to "why did we get two" on a screen instead of in a column nobody can see. It is also what stops
 * a second instance, or a restart within the hour, from sending the report twice.
 *
 * <p><b>Enabling it mid-week sends one immediately.</b> That is deliberate: an operator who switches
 * a notification on and receives nothing for six days concludes it does not work, and the next thing
 * they do is switch it off.
 *
 * <h2>What it does not do</h2>
 *
 * <p><b>One report for the deployment, not one per team.</b> The figures are the whole installation's
 * — {@code Visibility.everything()} — because this is the security team's feed, the same reasoning
 * that keeps the global webhook receiving every team's findings. A per-team digest is a different
 * feature: it would have to narrow every figure by that team's grants, and a report that quietly
 * counted targets its readers cannot open would leak precisely what the partitioning exists to
 * withhold.
 */
@Service
public class PostureDigestService {

    private static final Logger log = LoggerFactory.getLogger(PostureDigestService.class);

    /** The window the "this week" figures cover, and the one the trend is taken over. */
    private static final int WEEK_DAYS = 7;

    private final SettingsService settings;
    private final GateService gate;
    private final SlaService sla;
    private final Issues issues;
    private final AuditLog auditLog;
    private final AuditLogService audit;
    private final NotificationService webhook;
    private final MailNotificationChannel mail;
    private final OutboundPost post;
    private final Clock clock;

    public PostureDigestService(
            SettingsService settings,
            GateService gate,
            SlaService sla,
            Issues issues,
            AuditLog auditLog,
            AuditLogService audit,
            NotificationService webhook,
            MailNotificationChannel mail,
            OutboundPost post,
            Clock clock) {
        this.settings = settings;
        this.gate = gate;
        this.sla = sla;
        this.issues = issues;
        this.auditLog = auditLog;
        this.audit = audit;
        this.webhook = webhook;
        this.mail = mail;
        this.post = post;
        this.clock = clock;
    }

    /**
     * Sends this week's report if it is due and has not gone out.
     *
     * <p><b>Never throws.</b> This runs on the maintenance tick beside the purge and the triage
     * expiry, and a mail relay being down must not stop them. A failure is logged and left for the
     * next turn, which is the whole reason this needs no queue.
     *
     * @return true when a report was sent
     */
    public boolean runOnce() {
        try {
            return send();
        } catch (RuntimeException failed) {
            // No audit entry, deliberately: the entry is what records that a report went out, and
            // writing one for a failure would suppress every retry for the rest of the week.
            log.warn("The weekly posture report could not be sent; it will be retried next tick.", failed);
            return false;
        }
    }

    private boolean send() {
        if (!settings.isEnabled(Setting.DIGEST_ENABLED)) {
            return false;
        }

        Instant now = clock.instant();
        LocalDate weekStarting = LocalDate.ofInstant(now, ZoneOffset.UTC)
                .with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
        Instant since = weekStarting.atStartOfDay(ZoneOffset.UTC).toInstant();

        if (auditLog.countByOperationTypeAndTimestampGreaterThanEqual(
                        AuditOperation.POSTURE_DIGEST_SENT.wireName(), since)
                > 0) {
            return false;
        }

        boolean toWebhook = !webhook.webhookUrl().isEmpty();
        boolean toMail = mail.isConfigured();
        if (!toWebhook && !toMail) {
            // Nowhere to send is not a failure to retry hourly for a week. It is a deployment that
            // switched the report on and configured no destination, and the settings screen is
            // where that is visible.
            return false;
        }

        PostureDigest digest = PostureDigest.of(weekStarting, counts(now));

        if (toWebhook) {
            // Signed like every other webhook message, with the same secret: a report that says
            // "nothing is late" is exactly the message somebody would want to forge.
            post.postSignedJson(
                    webhook.webhookUrl(),
                    digest,
                    settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)
                            ? OutboundPolicy.INTERNAL_ALLOWED
                            : OutboundPolicy.PUBLIC_ONLY,
                    "weekly report webhook URL",
                    webhook.signingSecret(),
                    now);
        }
        if (toMail) {
            mail.sendText(digest.asSubject(), digest.asPlainText());
        }

        // **Written after the send, and this order is the choice.** Recording first would mean a
        // failed POST is never retried — the entry would say a report went out that did not. The
        // cost of this order is the reverse: a crash between the send and this write sends one
        // report twice next tick, which is a duplicate somebody can ignore rather than a week of
        // silence nobody can see.
        audit.record(new AuditLogService.Record(
                AuditOperation.POSTURE_DIGEST_SENT,
                weekStarting.toString(),
                "Weekly posture report sent"
                        + (toWebhook && toMail ? " to the webhook and by e-mail" : toWebhook ? " to the webhook" : " by e-mail")
                        + ": " + digest.openTotal() + " open, " + digest.overdueCount() + " late.",
                // No actor: nobody asked for this one, and inventing a "system" user would put a
                // person who does not exist into a compliance report.
                null,
                null,
                null));

        log.info("Weekly posture report sent for the week of {}.", weekStarting);
        return true;
    }

    /**
     * The figures, every one of them from a service that already computes it for a screen.
     *
     * <p>Nothing is recounted here on purpose: a report whose numbers are derived independently
     * ends up disagreeing with the dashboard, and it is the report that gets forwarded.
     */
    private PostureDigest.Counts counts(Instant now) {
        Visibility everything = Visibility.everything();
        SecurityOverview.Overview posture = gate.overview(everything);

        LocalDate to = LocalDate.ofInstant(now, ZoneOffset.UTC);
        BacklogTrend.Series week = BacklogTrend.over(
                issues.findAll(new IssueFilters(null, null, null, null, null, null, false, false, null, everything)
                                .toSpecification())
                        .stream()
                        .map(issue -> new BacklogTrend.Lifespan(issue.getFirstSeenAt(), issue.getResolvedAt()))
                        .toList(),
                to.minusDays(WEEK_DAYS - 1L),
                to);

        long openedThisWeek = week.points().stream().mapToLong(BacklogTrend.Point::opened).sum();
        long resolvedThisWeek = week.points().stream().mapToLong(BacklogTrend.Point::resolved).sum();
        long openTotal = week.points().isEmpty()
                ? 0
                : week.points().get(week.points().size() - 1).open();

        return new PostureDigest.Counts(
                openTotal,
                backlogBySeverity(everything),
                openedThisWeek,
                resolvedThisWeek,
                sla.countOverdue(everything),
                posture.failingCount(),
                posture.totalCount(),
                posture.neverScannedCount(),
                posture.lastScanFailedCount(),
                week.meanDaysToResolve());
    }

    /** The same per-severity counts the dashboard shows, and by the same clause. */
    private Map<String, Long> backlogBySeverity(Visibility allowed) {
        Map<String, Long> counts = new HashMap<>();
        for (Severity severity : Severity.values()) {
            long count = issues.count(new IssueFilters(
                            IssueState.OPEN.wireName(),
                            severity.wireName(),
                            null, null, null, null, false, false, null, allowed)
                    .toSpecification());
            if (count > 0) {
                counts.put(severity.wireName(), count);
            }
        }
        return counts;
    }
}

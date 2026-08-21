package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.notifications.NotificationPayload;
import com.asmolabs.zanshin.common.domain.notifications.NotificationPayload.NotifiableIssue;
import com.asmolabs.zanshin.common.domain.notifications.NotificationSelection;
import com.asmolabs.zanshin.common.domain.settings.Setting;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Sending what a scan changed.
 *
 * <p>This service owns <b>what to say and how to say it</b>; the outbox relay owns <b>when a
 * message gets another chance</b>. Keeping them apart is what makes the retry policy testable
 * with no webhook, and the payload testable with no clock.
 */
@Service
public class NotificationService implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

    private final SettingsService settings;
    private final OutboundPost post;

    public NotificationService(SettingsService settings, OutboundPost post) {
        this.settings = settings;
        this.post = post;
    }

    public String webhookUrl() {
        return settings.get(Setting.WEBHOOK_URL).trim();
    }

    /** Enabled means "a URL is configured": there is no other switch. */
    public boolean isEnabled() {
        return !webhookUrl().isEmpty();
    }

    public Severity minSeverity() {
        Severity configured = Severity.of(settings.get(Setting.NOTIFICATION_MIN_SEVERITY));
        // `of` falls back to UNKNOWN, which ranks last and would let everything through. A
        // misspelled setting must not silently turn the threshold off.
        return configured == Severity.UNKNOWN ? NotificationSelection.DEFAULT_MIN_SEVERITY : configured;
    }

    /**
     * Builds a scan delta's payload, or nothing when there is nothing to say.
     *
     * <p>Separate from sending because the two happen at different moments: the message is built
     * and queued <b>inside the transaction that commits the scan's results</b>, and delivered
     * later by the relay.
     */
    public Optional<NotificationPayload> buildScanDelta(
            String targetName,
            long scanId,
            List<NotifiableIssue> newIssues,
            List<NotifiableIssue> reopenedIssues,
            int resolvedCount) {

        if (!isEnabled()) {
            return Optional.empty();
        }

        NotificationSelection.Options options =
                new NotificationSelection.Options(minSeverity(), settings.isEnabled(Setting.NOTIFY_ON_KEV));
        List<NotifiableIssue> notableNew = NotificationSelection.notable(newIssues, options);
        List<NotifiableIssue> notableReopened = NotificationSelection.notable(reopenedIssues, options);
        if (notableNew.isEmpty() && notableReopened.isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(NotificationPayload.of(new NotificationPayload.Delta(
                targetName, scanId, notableNew, notableReopened, resolvedCount, options.minSeverity())));
    }

    /**
     * Posts a payload. <b>Throws on failure</b>, so the relay can retry it.
     *
     * <p>The opposite contract from the rest of this class, deliberately: a swallowed failure is
     * a failure never retried, which is the whole reason the outbox exists. It is the relay that
     * turns the exception back into "not fatal".
     *
     * <p><b>The URL is re-read and validated here</b>, not captured at queue time: an operator
     * fixing a typo must not have to re-run a scan to flush the pending notifications, and a
     * setting written straight into the database must not become an unchecked destination.
     */
    @Override
    public String type() {
        return OutboxService.TYPE_SCAN_DELTA;
    }

    /**
     * <b>The generic webhook is a channel like the other two</b>, and keeps the legacy type: rows
     * queued before Teams and mail existed still carry {@code scan_delta}, and they must keep
     * routing here rather than becoming messages of an unknown kind.
     */
    @Override
    public boolean isConfigured() {
        return !webhookUrl().isBlank();
    }

    @Override
    public void deliver(NotificationPayload payload) {
        OutboundPolicy policy = settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)
                ? OutboundPolicy.INTERNAL_ALLOWED
                : OutboundPolicy.PUBLIC_ONLY;

        post.postJson(webhookUrl(), payload, policy, "webhook URL");
        log.info(
                "Webhook notified for scan {} ({} new, {} reopened), message {}.",
                payload.scanId(),
                payload.newCount(),
                payload.reopenedCount(),
                payload.messageId());
    }
}

package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.notifications.MailMessage;
import com.asmolabs.vectispire.common.domain.notifications.NotificationPayload;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * The alert as an e-mail.
 *
 * <h2>The relay is infrastructure; the recipients are a setting</h2>
 *
 * <p>Two halves configured in two places, deliberately. <b>Where to send</b> — the host, the
 * port, the credentials — belongs to the deployment: it is the same for every message, it holds
 * a password, and a password has no business in a table this application exports. <b>Who
 * receives</b> changes with the team and belongs on the settings screen, where somebody can add
 * an address without a restart.
 *
 * <p>Absent when no host is configured, so a deployment that does not send mail carries no
 * sender, no channel and nothing queued — the same shape as the single sign-on.
 */
@Service
public class MailNotificationChannel implements NotificationChannel {

    private static final Logger log = LoggerFactory.getLogger(MailNotificationChannel.class);

    /** Stored in the outbox, so this string is a data contract. */
    public static final String TYPE = "scan_delta_mail";

    private final SettingsService settings;
    private final Optional<JavaMailSender> sender;
    private final ExportProperties deployment;
    private final String from;

    public MailNotificationChannel(
            SettingsService settings,
            Optional<JavaMailSender> sender,
            ExportProperties deployment,
            @org.springframework.beans.factory.annotation.Value("${vectispire.mail.from:vectispire@localhost}") String from) {
        this.settings = settings;
        this.sender = sender;
        this.deployment = deployment;
        this.from = from;
    }

    @Override
    public String type() {
        return TYPE;
    }

    /**
     * Both halves, because either alone sends nothing.
     *
     * <p>A configured relay with no recipient and a recipient with no relay are the two ways this
     * is half set up, and each would otherwise queue messages that can never leave — filling the
     * outbox with rows whose backoff runs to exhaustion.
     */
    @Override
    public boolean isConfigured() {
        return sender.isPresent() && !recipients().isEmpty();
    }

    @Override
    public void deliver(NotificationPayload payload) {
        JavaMailSender mailer = sender.orElseThrow(() ->
                new IllegalStateException("No mail relay is configured on this deployment."));
        List<String> to = recipients();
        if (to.isEmpty()) {
            throw new IllegalStateException("No recipient is configured for e-mail notifications.");
        }

        MailMessage.Content content = MailMessage.of(payload, deployment.publicUrl().orElse(null));

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to.toArray(String[]::new));
        message.setSubject(content.subject());
        message.setText(content.body());

        // Throws on failure, like every channel: the relay is what turns it into a retry, and a
        // swallowed failure is a failure never retried.
        mailer.send(message);
        log.info("Mail sent to {} recipient(s) for scan {}, message {}.",
                to.size(), payload.scanId(), payload.messageId());
    }

    /**
     * Sends a message this channel did not build.
     *
     * <p>For the weekly posture report, which is not a scan delta and has no business being bent
     * into {@link NotificationPayload} to reuse the path above — a payload with {@code scanId = 0}
     * and a synthesised {@code text} is a shape that lies, and the next reader believes it.
     *
     * <p>It lives here rather than in the digest service because the relay, the sender address and
     * the recipient list are this class's: a second place resolving "who receives Vectispire's mail"
     * would drift from the settings screen the first time either was edited.
     *
     * <p><b>Throws on failure, like {@code deliver}.</b> Its caller has no queue — a digest is
     * derived from the database and simply recomputed next tick — so the exception is what stops
     * the send from being recorded as having happened.
     */
    public void sendText(String subject, String body) {
        JavaMailSender mailer = sender.orElseThrow(() ->
                new IllegalStateException("No mail relay is configured on this deployment."));
        List<String> to = recipients();
        if (to.isEmpty()) {
            throw new IllegalStateException("No recipient is configured for e-mail notifications.");
        }

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to.toArray(String[]::new));
        message.setSubject(subject);
        message.setText(body);
        mailer.send(message);
        log.info("Mail sent to {} recipient(s): {}", to.size(), subject);
    }

    private List<String> recipients() {
        return Arrays.stream(settings.get(Setting.MAIL_RECIPIENTS).split(","))
                .map(String::trim)
                .filter(address -> !address.isEmpty())
                .toList();
    }
}

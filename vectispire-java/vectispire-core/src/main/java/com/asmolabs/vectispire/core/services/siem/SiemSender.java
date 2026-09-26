package com.asmolabs.vectispire.core.services.siem;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.net.OutboundUrlGuard;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SiemEndpoint;
import com.asmolabs.vectispire.common.domain.siem.SyslogMessage;
import com.asmolabs.vectispire.core.services.outbound.OutboundJson;
import com.asmolabs.vectispire.core.services.outbound.OutboundPost;
import com.asmolabs.vectispire.core.services.shared.ProductVersion;
import com.asmolabs.vectispire.core.services.shared.SettingsService;
import java.net.InetAddress;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Sends one CEF event over the transport the configuration names.
 *
 * <p>The one place the protocol is honoured. It was stored and ignored: every event left as an HTTP
 * POST, whatever the screen said, and a collector listening for syslog received nothing.
 *
 * <ul>
 *   <li><b>Webhook</b>: a JSON POST {@code {"cef": "…"}} through {@link OutboundPost}, hence the
 *       pinned sender, no redirects — the body the exporter has always sent, so existing receivers
 *       keep working. The authorization header goes with it.
 *   <li><b>Syslog</b>: the host and port through {@link OutboundUrlGuard#validateAndResolveEndpoint}
 *       — the same classifier as a URL, reserved endpoints included — then RFC 5424 over the pinned
 *       address. <b>No header</b>: a syslog frame has nowhere to carry one.
 * </ul>
 *
 * <p>Both refuse a private destination unless {@code notification_allow_private_url} is on, as every
 * outbound channel does — a collector on an internal network needs that setting — and the metadata
 * endpoint, the Docker proxy and the database under every policy.
 */
@Component
public class SiemSender {

    /** Like {@link OutboundPost}'s: long enough for a slow collector, short enough not to hold the relay. */
    static final Duration TIMEOUT = Duration.ofSeconds(10);

    private static final String LABEL = "SIEM export";

    private final OutboundPost post;
    private final OutboundUrlGuard guard;
    private final SyslogSender syslog;
    private final SettingsService settings;
    private final ProductVersion version;

    /** Resolved on first use: a reverse lookup at startup can block on a host whose DNS is unwell. */
    private volatile String hostname;

    public SiemSender(
            OutboundPost post,
            OutboundUrlGuard guard,
            SyslogSender syslog,
            SettingsService settings,
            ProductVersion version) {
        this.post = post;
        this.guard = guard;
        this.syslog = syslog;
        this.settings = settings;
        this.version = version;
    }

    /**
     * Sends, or throws — an {@link OutboundJson.OutboundFailureException} for an unreachable or
     * refusing collector, an {@code UnsafeUrlException} for a destination the guard refuses. The
     * outbox retries either; the connection test reports it.
     *
     * @param authHeader sent with a webhook only, ignored for syslog; {@code null} for none
     */
    public void send(SiemEndpoint endpoint, String authHeader, CefEvent event) {
        String cef = event.toCefString(version.get());
        switch (endpoint) {
            case SiemEndpoint.Webhook webhook -> {
                Map<String, String> headers = new HashMap<>();
                if (authHeader != null && !authHeader.isBlank()) {
                    headers.put("Authorization", authHeader);
                }
                post.postForResponse(webhook.url(), Map.of("cef", cef), policy(), LABEL, headers, TIMEOUT);
            }
            case SiemEndpoint.Syslog collector -> {
                OutboundUrlGuard.Destination destination =
                        guard.validateAndResolveEndpoint(collector.host(), collector.port(), policy(), LABEL);
                String message = SyslogMessage.format(event.eventType(), event.timestamp(), hostname(), cef);
                syslog.send(collector.protocol(), destination, collector.port(), message, TIMEOUT, LABEL);
            }
        }
    }

    /**
     * Private addresses only when the operator has allowed them, as for every other channel.
     *
     * <p>Unconditionally allowed once. With the test route answering the raw error to a security
     * lead — "Connection refused", "HTTP 404" — that made a scanner of the internal network available
     * to a role that is not an administrator.
     */
    private OutboundPolicy policy() {
        return settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)
                ? OutboundPolicy.INTERNAL_ALLOWED
                : OutboundPolicy.PUBLIC_ONLY;
    }

    /**
     * The HOSTNAME a syslog header states: the container's or the machine's name, or the NILVALUE.
     * {@link SyslogMessage} strips anything a header token may not hold.
     */
    private String hostname() {
        String known = hostname;
        if (known == null) {
            String fromEnvironment = System.getenv("HOSTNAME");
            if (fromEnvironment != null && !fromEnvironment.isBlank()) {
                known = fromEnvironment;
            } else {
                try {
                    known = InetAddress.getLocalHost().getHostName();
                } catch (Exception unknown) {
                    known = "-";
                }
            }
            hostname = known;
        }
        return known;
    }
}

package com.asmolabs.vectispire.core.siem;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.net.UnsafeUrlException;
import com.asmolabs.vectispire.common.domain.settings.SettingType;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.CollectorCa;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.siem.SiemEndpoint;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.siem.internal.SiemSender;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The SIEM export's configuration and its connection test.
 *
 * <p>Events themselves do not pass here: they are queued by {@link SiemEvents} in the transaction
 * that caused them and sent by {@link SiemDelivery} after it commits. This class used to send them
 * — from an {@code @Async} method in a codebase with no {@code @EnableAsync}, so synchronously and
 * inside the caller's transaction, and always over HTTP whatever the protocol said.
 *
 * <p><b>Each transport is an integration</b> (decision 0040, {@code siem.<protocol>}): an enabled export is
 * not saved over a disabled one, nor is one tested, and the governor cannot switch off the one an enabled
 * export uses ({@code SiemTransportInUse}). The two checks meet on the registry's row, which the save
 * holds until it commits ({@link Integrations#holdEnabled}).
 */
@Service
public class SiemExporterService {

    private static final Logger log = LoggerFactory.getLogger(SiemExporterService.class);

    /** Binds the stored header to its own column, so a ciphertext moved elsewhere does not decrypt. */
    static final String AUTH_HEADER_CONTEXT = "siem_config:auth_header";

    /** The width of {@code endpoint}. */
    private static final int MAX_ENDPOINT_LENGTH = 1024;

    /** Encrypted, 1,500 ASCII characters become at most 2,043: see V32 and {@link #requireUsableHeader}. */
    private static final int MAX_AUTH_HEADER_LENGTH = 1_500;

    private final SiemConfigRepository repository;
    private final SiemSender sender;
    private final Integrations integrations;
    private final EncryptionService encryption;
    private final AuditLogService audit;
    private final Clock clock;

    /**
     * Opened explicitly, for the reason {@code ScanDispatcher} gives: the save's transaction is opened from
     * inside this class, and it must close before the stop notice leaves and the audit entry is written.
     */
    private final TransactionTemplate transactions;

    public SiemExporterService(
            SiemConfigRepository repository,
            SiemSender sender,
            Integrations integrations,
            EncryptionService encryption,
            AuditLogService audit,
            Clock clock,
            TransactionTemplate transactions) {
        this.repository = repository;
        this.sender = sender;
        this.integrations = integrations;
        this.encryption = encryption;
        this.audit = audit;
        this.clock = clock;
        this.transactions = transactions;
    }

    public Optional<SiemConfigView> getConfig() {
        return repository.findById(SiemConfigEntity.SINGLETON_ID).map(SiemConfigView::of);
    }

    /**
     * Stores the configuration and audits the change — never the header, which is a credential and
     * the audit log is never purged.
     *
     * @param tlsCaPem the collector CA for syslog over TLS: {@code null} keeps the stored one, blank
     *     removes it. Absent keeps because a client written before the field existed would otherwise
     *     unpin the CA at every save; the screen always sends what it shows
     * @throws com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException an enabled
     *     export over a transport the governor has disabled: 409 {@code integration-disabled}. A disabled
     *     export is saved over any protocol — it sends over none, and switching the export off must never be
     *     what a disabled transport prevents
     */
    public SiemConfigView saveConfig(
            boolean enabled,
            String protocol,
            String endpoint,
            String authHeader,
            String minSeverity,
            String tlsCaPem,
            RequestActor actor) {
        // Every field is checked before the row is touched, so a refusal leaves the stored
        // configuration exactly as it was. Each of these reached its column unchecked, and a value
        // past it was refused by the database at the write, as a 500.
        SiemProtocol parsedProtocol = protocol == null || protocol.isBlank()
                ? SiemProtocol.WEBHOOK
                : parseProtocol(protocol);
        Integration transport = Integration.of(parsedProtocol);
        if (enabled) {
            // Asked first, so the refusal comes before the form's other words; asked again, and held, in
            // the transaction that writes the row.
            integrations.requireEnabled(transport);
        }
        Severity threshold = minSeverity == null || minSeverity.isBlank()
                ? Severity.HIGH
                : SettingType.THRESHOLDS.stream()
                        .filter(candidate -> candidate.wireName().equalsIgnoreCase(minSeverity.trim()))
                        .findFirst()
                        .orElseThrow(() -> new InvalidInputException(
                                "Unknown minimum severity \"" + minSeverity.trim()
                                        + "\". Expected one of: CRITICAL, HIGH, MEDIUM, LOW."));
        BoundedText.within(endpoint == null ? null : endpoint.trim(), MAX_ENDPOINT_LENGTH, "The endpoint");
        // **Read for its protocol at the save, not discovered at the first event.** A syslog
        // endpoint typed as a URL, or a URL saved under a syslog protocol, used to be stored and then
        // fail every delivery for four hours before the outbox gave up. An enabled export with no
        // endpoint is refused too: it would have queued nothing and said so to nobody.
        boolean hasEndpoint = endpoint != null && !endpoint.isBlank();
        if (hasEndpoint) {
            SiemEndpoint.parse(parsedProtocol, endpoint);
        } else if (enabled) {
            throw new InvalidInputException("An enabled SIEM export needs an endpoint.");
        }
        if (authHeader != null && !authHeader.isBlank()) {
            if (!parsedProtocol.carriesHeaders()) {
                // Refused rather than stored: a credential kept for a transport that cannot send it
                // is a secret at rest with no purpose, and the screen would claim it was in use.
                throw new InvalidInputException(
                        "The authorization header applies to the webhook protocol only: a syslog frame has "
                                + "nowhere to carry it.");
            }
            requireUsableHeader(authHeader.trim());
        }
        boolean caGiven = tlsCaPem != null && !tlsCaPem.isBlank();
        if (caGiven && parsedProtocol != SiemProtocol.SYSLOG_TLS) {
            // Refused rather than stored, like a header sent for syslog: the screen would show a CA
            // as pinned for a transport that never reads it.
            throw new InvalidInputException(
                    "A collector CA applies to syslog over TLS only: the other protocols do not verify a "
                            + "collector's certificate against it.");
        }
        CollectorCa pinned = caGiven ? CollectorCa.parse(tlsCaPem, clock.instant()) : null;

        Written written = transactions.execute(status -> {
            if (enabled) {
                // **Held until the row commits.** Checked and not held, a governor's switch could read
                // "not in use" between this check and the commit, and the export would stand on a
                // transport that is off — its events held in the outbox until somebody noticed.
                integrations.holdEnabled(transport);
            }
            return write(enabled, parsedProtocol, endpoint, authHeader, threshold, tlsCaPem, pinned);
        });
        SiemConfigEntity saved = written.saved();

        // The collector being left hears it, before the silence: a feed that stops is otherwise
        // read by a SOC as an outage — or not noticed at all — when it was a decision, possibly by
        // somebody covering their tracks. Sent after the save has committed — no outbound call holds
        // the row — so it announces a change that happened, and before the audit entry, which records
        // whether it arrived.
        String notice = written.leaving()
                .filter(previous -> !saved.isEnabled() || !previous.sameDestinationAs(saved))
                .map(previous -> announceStop(previous, saved.isEnabled(), actor))
                .orElse("");

        // Signalled, and sent to the collector configured by this very save when it is on: a SOC
        // should hear about the export being repointed, at the new collector as at the old one.
        audit.record(actor.entry(
                        AuditOperation.SETTING_UPDATED,
                        String.valueOf(saved.getId()),
                        "SIEM configuration updated (enabled=" + saved.isEnabled() + ", protocol=" + saved.getProtocol()
                                + ", minimum severity=" + saved.getMinSeverity()
                                + (saved.getTlsCaPem() != null ? ", collector CA pinned" : "") + ")" + notice)
                .signalling(SecurityEventType.SECURITY_SETTING_CHANGED));
        return SiemConfigView.of(saved);
    }

    /** The row as the save left it, and the collector it was exporting to before. */
    private record Written(SiemConfigEntity saved, Optional<Collector> leaving) {}

    /** Writes the checked configuration onto the row; runs inside the save's transaction. */
    private Written write(
            boolean enabled,
            SiemProtocol parsedProtocol,
            String endpoint,
            String authHeader,
            Severity threshold,
            String tlsCaPem,
            CollectorCa pinned) {
        SiemConfigEntity entity = repository.findById(SiemConfigEntity.SINGLETON_ID)
                .orElseGet(() -> {
                    SiemConfigEntity fresh = new SiemConfigEntity();
                    fresh.setId(SiemConfigEntity.SINGLETON_ID);
                    return fresh;
                });
        // Read before the row changes: the collector being left is the one configured now.
        Optional<Collector> leaving = collectorOf(entity);
        // **A new destination does not inherit the old credential.** "Blank keeps the header" was
        // right for a save that changed the severity, and it also held when the endpoint changed:
        // the header an administrator had stored left for whatever collector the new URL named —
        // the security lead's own host included — without anyone having re-entered it. A header is
        // issued for one collector; pointing elsewhere now requires typing it again.
        String previousEndpoint = entity.getEndpoint() == null ? "" : entity.getEndpoint().trim();
        String nextEndpoint = endpoint == null ? "" : endpoint.trim();
        boolean destinationMoved = !previousEndpoint.equals(nextEndpoint);
        if (destinationMoved && (authHeader == null || authHeader.isBlank())) {
            entity.setAuthHeader(null);
        }
        entity.setEnabled(enabled);
        entity.setProtocol(parsedProtocol.name());
        entity.setEndpoint(endpoint);
        // **Blank keeps the stored header.** The screen says so ("leave empty to keep current")
        // and the response never sends the header back, so the form cannot resubmit it: writing
        // what arrived erased the credential on every save that changed anything else, and the
        // exports then went out unauthenticated and were refused by the collector.
        //
        // **Encrypted like every other credential**, which this one was not: it sat in the
        // database as typed, readable by anyone holding a backup.
        if (authHeader != null && !authHeader.isBlank()) {
            entity.setAuthHeader(encryption.encrypt(authHeader.trim(), AUTH_HEADER_CONTEXT));
        }
        if (parsedProtocol != SiemProtocol.SYSLOG_TLS || (tlsCaPem != null && tlsCaPem.isBlank())) {
            // Leaving TLS drops the CA with it: kept, it would come back unannounced the day the
            // protocol is set to TLS again, for a collector it was perhaps never issued for.
            entity.setTlsCaPem(null);
        } else if (pinned != null) {
            entity.setTlsCaPem(pinned.pem());
        }
        // Stored in capitals, as the screen sends it and the default has always been written.
        entity.setMinSeverity(threshold.name());
        entity.setUpdatedAt(Instant.now());
        return new Written(repository.save(entity), leaving);
    }

    /**
     * The collector a stored configuration exports to, with what it takes to reach it — or empty
     * when it exports nowhere, or its row can no longer be read (then there is no collector to
     * tell, and the delivery would have refused it too).
     */
    private Optional<Collector> collectorOf(SiemConfigEntity row) {
        Optional<SiemProtocol> known = SiemProtocol.byName(row.getProtocol());
        if (!row.isEnabled() || row.getEndpoint() == null || row.getEndpoint().isBlank() || known.isEmpty()) {
            return Optional.empty();
        }
        try {
            SiemProtocol protocol = known.get();
            SiemEndpoint endpoint = SiemEndpoint.parse(protocol, row.getEndpoint());
            String header = protocol.carriesHeaders() && row.getAuthHeader() != null
                    ? encryption.readSecret(row.getAuthHeader(), AUTH_HEADER_CONTEXT, "The SIEM authorization header")
                    : null;
            // Checked current, as the delivery checks it: the JDK does not read a trust anchor's
            // dates, and a lapsed CA must not vouch for the collector even for a last message. Such
            // a collector cannot be verified, so it is not told.
            Optional<CollectorCa> ca = protocol == SiemProtocol.SYSLOG_TLS && row.getTlsCaPem() != null
                    ? Optional.of(CollectorCa.parse(row.getTlsCaPem(), clock.instant()))
                    : Optional.empty();
            return Optional.of(new Collector(protocol, row.getEndpoint().trim(), endpoint, header, ca));
        } catch (RuntimeException unreadable) {
            log.warn("The SIEM collector being left could not be read, so it was not told: {}", unreadable.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Sends {@link SecurityEventType#SIEM_EXPORT_STOPPED} to the collector being left, synchronously,
     * and says in words for the audit entry whether it arrived.
     *
     * <p><b>Not through the outbox</b>, which reads the destination when the message leaves — by
     * then the configuration no longer names this collector, and the event would be abandoned as
     * "switched off". <b>Not filtered by the minimum severity</b>: it is about the channel, like the
     * connection test, and a threshold set to critical must not swallow the one message that
     * explains the silence after it. <b>Best effort</b>: a collector that is down does not stop the
     * export being switched off — the audit entry says the notice did not arrive, and the detail
     * goes to the server log, as for the connection test.
     *
     * <p>The new destination is not named: the collector being left has no business learning where
     * the feed went.
     *
     * <p><b>Not over a disabled transport.</b> The governor cannot switch off the one an enabled export
     * uses, so this is a row written by hand; nothing of a disabled integration runs, and the audit entry
     * says the notice was not sent and why.
     */
    private String announceStop(Collector previous, boolean redirected, RequestActor actor) {
        Integration transport = Integration.of(previous.protocol());
        if (!integrations.isEnabled(transport)) {
            return "; stop notice NOT sent to the previous collector: its transport " + transport.key() + " is disabled";
        }
        CefEvent stopped = CefEvent.builder(SecurityEventType.SIEM_EXPORT_STOPPED)
                .message(redirected
                        ? "The SIEM export was pointed at another collector: this one will receive no further events."
                        : "The SIEM export was switched off: no further events will be sent until it is switched back on.")
                .user(actor.username())
                .sourceIp(actor.ipAddress())
                .action(AuditOperation.SETTING_UPDATED.wireName())
                .target(String.valueOf(SiemConfigEntity.SINGLETON_ID))
                .userAgent(actor.userAgent())
                .build();
        try {
            sender.send(previous.endpoint(), previous.header(), previous.ca(), stopped);
            return "; stop notice delivered to the previous collector";
        } catch (RuntimeException failed) {
            log.warn("The SIEM stop notice to {} over {} was not delivered: {}", previous.written(), previous.protocol(),
                    failed.getMessage());
            return "; stop notice NOT delivered to the previous collector (the cause is in the server log)";
        }
    }

    /** A collector as a configuration names it: the written endpoint, what was read of it, how to reach it. */
    private record Collector(
            SiemProtocol protocol, String written, SiemEndpoint endpoint, String header, Optional<CollectorCa> ca) {

        /** The same transport to the same endpoint as written: a new severity or header does not leave it. */
        boolean sameDestinationAs(SiemConfigEntity row) {
            return protocol.name().equals(row.getProtocol())
                    && row.getEndpoint() != null
                    && written.equals(row.getEndpoint().trim());
        }
    }

    /**
     * A header value that can be sent, and whose ciphertext fits the column.
     *
     * <p>Visible ASCII and spaces only: that is what an HTTP field value may carry, and a line break
     * in it is a header injection on every export. Bounded so that, encrypted — a third longer and
     * forty characters of envelope — it stays inside the 2,048 characters V32 gave the column.
     */
    private static void requireUsableHeader(String header) {
        BoundedText.within(header, MAX_AUTH_HEADER_LENGTH, "The authorization header");
        if (!header.chars().allMatch(c -> c >= 0x20 && c < 0x7f)) {
            throw new InvalidInputException(
                    "The authorization header may hold printable ASCII only: no line break, no control or "
                            + "accented character.");
        }
    }

    /**
     * Sends the health-check event, synchronously, over the protocol given — or the stored one when
     * none is — so the button tests the transport the export will actually use. It tested HTTP
     * whatever the protocol said, and a working syslog collector was reported unreachable.
     *
     * <p>Reported rather than thrown: "unreachable" is the answer to the question the button asks.
     * The same guard runs as for a real event, so a refusal here is the refusal the export would
     * get. The header travels with a webhook only.
     *
     * <p><b>An outcome, not the error.</b> The route answered the socket's own words — "Connection
     * refused", "Read timed out", "HTTP 404" — to a security lead, and those tell a closed port from a
     * filtered one from a listening web server: a scanner of whatever network the policy lets the
     * export reach. Three outcomes now — delivered, refused by the policy, not delivered — and the
     * detail goes to the server log, where an administrator reads it.
     *
     * @param tlsCaPem the collector CA to verify against, for syslog over TLS: {@code null} tests the
     *     stored one, blank tests the runtime's trust store — so the button tests the CA on the form,
     *     saved or not
     * @throws com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException the transport
     *     tested — given, or the stored one — is disabled: 409 {@code integration-disabled}, nothing sent.
     *     Thrown, not reported: it is not an answer about the collector, and a test that answered "not
     *     delivered" would send the security lead to look at a network that is fine
     */
    public TestResult testConnection(String protocol, String endpoint, String authHeader, String tlsCaPem) {
        if (endpoint == null || endpoint.isBlank()) {
            return new TestResult(false, "An endpoint is required.", 0);
        }
        SiemProtocol parsed;
        SiemEndpoint destination;
        Optional<CollectorCa> pinned;
        try {
            parsed = protocol == null || protocol.isBlank()
                    ? getConfig().flatMap(config -> SiemProtocol.byName(config.protocol())).orElse(SiemProtocol.WEBHOOK)
                    : parseProtocol(protocol);
            // Not an IllegalArgumentException, so it leaves this block as the 409 it is.
            integrations.requireEnabled(Integration.of(parsed));
            destination = SiemEndpoint.parse(parsed, endpoint);
            String ca = tlsCaPem != null ? tlsCaPem : getConfig().map(SiemConfigView::tlsCaPem).orElse(null);
            pinned = parsed == SiemProtocol.SYSLOG_TLS && ca != null && !ca.isBlank()
                    ? Optional.of(CollectorCa.parse(ca, clock.instant()))
                    : Optional.empty();
        } catch (IllegalArgumentException refused) {
            return new TestResult(false, refused.getMessage(), 0);
        }
        try {
            CefEvent ping = CefEvent.builder(SecurityEventType.PING_TEST)
                    .message("Vectispire SIEM health check")
                    .build();
            sender.send(destination, parsed.carriesHeaders() ? authHeader : null, pinned, ping);
            return new TestResult(true, "Event delivered over " + parsed.name() + ".", parsed.carriesHeaders() ? 200 : 0);
        } catch (UnsafeUrlException refused) {
            log.warn("SIEM connection test refused by the outbound policy: {}", refused.getMessage());
            return new TestResult(false, REFUSED_BY_POLICY, 0);
        } catch (Exception failed) {
            log.warn("SIEM connection test over {} failed: {}", parsed.name(), failed.getMessage());
            return new TestResult(false, NOT_DELIVERED, 0);
        }
    }

    static final String REFUSED_BY_POLICY = "Refused by the outbound policy: this destination is not allowed. A "
            + "collector on the internal network needs an administrator to enable “Allow a private SIEM "
            + "destination”; Vectispire's own database, its Docker daemon and the instance metadata endpoint "
            + "are refused in every case.";

    static final String NOT_DELIVERED = "The event was not delivered: the collector could not be reached, or did "
            + "not accept it. The cause is in the server log.";

    private static SiemProtocol parseProtocol(String protocol) {
        return SiemProtocol.byName(protocol).orElseThrow(() -> new InvalidInputException(
                "Unknown SIEM protocol \"" + protocol.trim() + "\". Expected one of: "
                        + String.join(", ", Arrays.stream(SiemProtocol.values()).map(Enum::name).toList()) + "."));
    }

    public record TestResult(boolean success, String message, int statusCode) {}
}

package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.settings.SettingType;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.siem.SiemEndpoint;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.repositories.SiemConfigs;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * The SIEM export's configuration and its connection test.
 *
 * <p>Events themselves do not pass here: they are queued by {@link SiemEvents} in the transaction
 * that caused them and sent by {@link SiemDelivery} after it commits. This class used to send them
 * — from an {@code @Async} method in a codebase with no {@code @EnableAsync}, so synchronously and
 * inside the caller's transaction, and always over HTTP whatever the protocol said.
 */
@Service
public class SiemExporterService {

    /** Binds the stored header to its own column, so a ciphertext moved elsewhere does not decrypt. */
    static final String AUTH_HEADER_CONTEXT = "siem_config:auth_header";

    /** The width of {@code endpoint}. */
    private static final int MAX_ENDPOINT_LENGTH = 1024;

    /** Encrypted, 1,500 ASCII characters become at most 2,043: see V32 and {@link #requireUsableHeader}. */
    private static final int MAX_AUTH_HEADER_LENGTH = 1_500;

    private final SiemConfigs repository;
    private final SiemSender sender;
    private final EncryptionService encryption;
    private final AuditLogService audit;

    public SiemExporterService(
            SiemConfigs repository,
            SiemSender sender,
            EncryptionService encryption,
            AuditLogService audit) {
        this.repository = repository;
        this.sender = sender;
        this.encryption = encryption;
        this.audit = audit;
    }

    public Optional<SiemConfigEntity> getConfig() {
        return repository.findById(SiemConfigEntity.SINGLETON_ID);
    }

    /**
     * Stores the configuration and audits the change — never the header, which is a credential and
     * the audit log is never purged.
     */
    public SiemConfigEntity saveConfig(
            boolean enabled, String protocol, String endpoint, String authHeader, String minSeverity, RequestActor actor) {
        // Every field is checked before the row is touched, so a refusal leaves the stored
        // configuration exactly as it was. Each of these reached its column unchecked, and a value
        // past it was refused by the database at the write, as a 500.
        SiemProtocol parsedProtocol = protocol == null || protocol.isBlank()
                ? SiemProtocol.WEBHOOK
                : parseProtocol(protocol);
        Severity threshold = minSeverity == null || minSeverity.isBlank()
                ? Severity.HIGH
                : SettingType.THRESHOLDS.stream()
                        .filter(candidate -> candidate.wireName().equalsIgnoreCase(minSeverity.trim()))
                        .findFirst()
                        .orElseThrow(() -> new IllegalArgumentException(
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
            throw new IllegalArgumentException("An enabled SIEM export needs an endpoint.");
        }
        if (authHeader != null && !authHeader.isBlank()) {
            if (!parsedProtocol.carriesHeaders()) {
                // Refused rather than stored: a credential kept for a transport that cannot send it
                // is a secret at rest with no purpose, and the screen would claim it was in use.
                throw new IllegalArgumentException(
                        "The authorization header applies to the webhook protocol only: a syslog frame has "
                                + "nowhere to carry it.");
            }
            requireUsableHeader(authHeader.trim());
        }

        SiemConfigEntity entity = repository.findById(SiemConfigEntity.SINGLETON_ID)
                .orElseGet(() -> {
                    SiemConfigEntity fresh = new SiemConfigEntity();
                    fresh.setId(SiemConfigEntity.SINGLETON_ID);
                    return fresh;
                });
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
        // Stored in capitals, as the screen sends it and the default has always been written.
        entity.setMinSeverity(threshold.name());
        entity.setUpdatedAt(Instant.now());
        SiemConfigEntity saved = repository.save(entity);

        // Signalled, and sent to the collector configured by this very save when it is on: a SOC
        // should hear about the export being repointed — and, when it is switched off, the silence
        // that follows is itself the signal, which is why nothing tries to send "switched off".
        audit.record(actor.entry(
                        AuditOperation.SETTING_UPDATED,
                        String.valueOf(saved.getId()),
                        "SIEM configuration updated (enabled=" + saved.isEnabled() + ", protocol=" + saved.getProtocol()
                                + ", minimum severity=" + saved.getMinSeverity() + ")")
                .signalling(SecurityEventType.SECURITY_SETTING_CHANGED));
        return saved;
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
            throw new IllegalArgumentException(
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
     */
    public TestResult testConnection(String protocol, String endpoint, String authHeader) {
        if (endpoint == null || endpoint.isBlank()) {
            return new TestResult(false, "An endpoint is required.", 0);
        }
        SiemProtocol parsed;
        SiemEndpoint destination;
        try {
            parsed = protocol == null || protocol.isBlank()
                    ? getConfig().flatMap(config -> SiemProtocol.byName(config.getProtocol())).orElse(SiemProtocol.WEBHOOK)
                    : parseProtocol(protocol);
            destination = SiemEndpoint.parse(parsed, endpoint);
        } catch (IllegalArgumentException refused) {
            return new TestResult(false, refused.getMessage(), 0);
        }
        try {
            CefEvent ping = CefEvent.builder(SecurityEventType.PING_TEST)
                    .message("Vectispire SIEM health check")
                    .build();
            sender.send(destination, parsed.carriesHeaders() ? authHeader : null, ping);
            return new TestResult(true, "Event delivered over " + parsed.name() + ".", parsed.carriesHeaders() ? 200 : 0);
        } catch (Exception e) {
            return new TestResult(false, "Connection error: " + e.getMessage(), 0);
        }
    }

    private static SiemProtocol parseProtocol(String protocol) {
        return SiemProtocol.byName(protocol).orElseThrow(() -> new IllegalArgumentException(
                "Unknown SIEM protocol \"" + protocol.trim() + "\". Expected one of: "
                        + String.join(", ", Arrays.stream(SiemProtocol.values()).map(Enum::name).toList()) + "."));
    }

    public record TestResult(boolean success, String message, int statusCode) {}
}

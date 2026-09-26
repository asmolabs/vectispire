package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.settings.SettingType;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.repositories.SiemConfigs;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Dispatches security events to external SIEM & SOC aggregators in ArcSight CEF v0.1 format.
 *
 * <p>Uses {@link OutboundPost} to respect the strict outbound door and SSRF protection rules.
 */
@Service
public class SiemExporterService {

    /** Binds the stored header to its own column, so a ciphertext moved elsewhere does not decrypt. */
    static final String AUTH_HEADER_CONTEXT = "siem_config:auth_header";

    /** The width of {@code endpoint}. */
    private static final int MAX_ENDPOINT_LENGTH = 1024;

    /** Encrypted, 1,500 ASCII characters become at most 2,043: see V32 and {@link #requireUsableHeader}. */
    private static final int MAX_AUTH_HEADER_LENGTH = 1_500;

    private static final Logger log = LoggerFactory.getLogger(SiemExporterService.class);
    private final SiemConfigs repository;
    private final OutboundPost outbound;
    private final EncryptionService encryption;
    private final SettingsService settings;
    private final AuditLogService audit;
    private final ProductVersion version;

    public SiemExporterService(
            SiemConfigs repository,
            OutboundPost outbound,
            EncryptionService encryption,
            SettingsService settings,
            AuditLogService audit,
            ProductVersion version) {
        this.repository = repository;
        this.outbound = outbound;
        this.encryption = encryption;
        this.settings = settings;
        this.audit = audit;
        this.version = version;
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
                : SiemProtocol.byName(protocol).orElseThrow(() -> new IllegalArgumentException(
                        "Unknown SIEM protocol \"" + protocol.trim() + "\". Expected one of: "
                                + String.join(", ", Arrays.stream(SiemProtocol.values()).map(Enum::name).toList())
                                + "."));
        Severity threshold = minSeverity == null || minSeverity.isBlank()
                ? Severity.HIGH
                : SettingType.THRESHOLDS.stream()
                        .filter(candidate -> candidate.wireName().equalsIgnoreCase(minSeverity.trim()))
                        .findFirst()
                        .orElseThrow(() -> new IllegalArgumentException(
                                "Unknown minimum severity \"" + minSeverity.trim()
                                        + "\". Expected one of: CRITICAL, HIGH, MEDIUM, LOW."));
        BoundedText.within(endpoint == null ? null : endpoint.trim(), MAX_ENDPOINT_LENGTH, "The endpoint");
        if (authHeader != null && !authHeader.isBlank()) {
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

        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED,
                String.valueOf(saved.getId()),
                "SIEM configuration updated (enabled=" + saved.isEnabled() + ", protocol=" + saved.getProtocol() + ")"));
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

    @Async
    public void exportEvent(CefEvent event) {
        getConfig().ifPresent(config -> {
            if (!config.isEnabled() || config.getEndpoint() == null || config.getEndpoint().isBlank()) {
                return;
            }
            try {
                sendPayload(config.getEndpoint(), storedAuthHeader(config), event.toCefString(version.get()));
            } catch (Exception e) {
                log.warn("Failed to export SIEM security event: {}", e.getMessage());
            }
        });
    }

    public TestResult testConnection(String endpoint, String authHeader) {
        if (endpoint == null || endpoint.isBlank()) {
            return new TestResult(false, "Endpoint URL is required", 0);
        }
        try {
            CefEvent testEvent = CefEvent.builder(SecurityEventType.PING_TEST)
                    .message("Vectispire SIEM Health Check Ping")
                    .build();
            sendPayload(endpoint, authHeader, testEvent.toCefString(version.get()));
            return new TestResult(true, "Event delivered successfully", 200);
        } catch (Exception e) {
            return new TestResult(false, "Connection error: " + e.getMessage(), 0);
        }
    }

    /** Tolerates a header stored before it was encrypted, with a warning — see {@code readSecret}. */
    private String storedAuthHeader(SiemConfigEntity config) {
        return encryption.readSecret(config.getAuthHeader(), AUTH_HEADER_CONTEXT, "The SIEM authorization header");
    }

    /**
     * Private addresses only when the operator has allowed them, as for every other channel.
     *
     * <p>This one allowed them unconditionally. With the test route answering the raw error to a
     * security lead — "Connection refused", "HTTP 404" — that made a scanner of the internal
     * network available to a role that is not an administrator. The metadata endpoint stays
     * refused under both policies.
     */
    private OutboundPolicy policy() {
        return settings.isEnabled(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)
                ? OutboundPolicy.INTERNAL_ALLOWED
                : OutboundPolicy.PUBLIC_ONLY;
    }

    private void sendPayload(String endpoint, String authHeader, String cefString) {
        Map<String, String> headers = new HashMap<>();
        if (authHeader != null && !authHeader.isBlank()) {
            headers.put("Authorization", authHeader);
        }
        Map<String, String> payload = Map.of("cef", cefString);
        outbound.postForResponse(endpoint, payload, policy(), "SIEM export", headers);
    }

    public record TestResult(boolean success, String message, int statusCode) {}
}

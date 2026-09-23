package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.net.OutboundPolicy;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.core.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.repositories.SiemConfigs;
import java.time.Instant;
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

    private static final Logger log = LoggerFactory.getLogger(SiemExporterService.class);
    private final SiemConfigs repository;
    private final OutboundPost outbound;
    private final EncryptionService encryption;
    private final SettingsService settings;

    public SiemExporterService(
            SiemConfigs repository, OutboundPost outbound, EncryptionService encryption, SettingsService settings) {
        this.repository = repository;
        this.outbound = outbound;
        this.encryption = encryption;
        this.settings = settings;
    }

    public Optional<SiemConfigEntity> getConfig() {
        return repository.findById(SiemConfigEntity.SINGLETON_ID);
    }

    public SiemConfigEntity saveConfig(boolean enabled, String protocol, String endpoint, String authHeader, String minSeverity) {
        SiemConfigEntity entity = repository.findById(SiemConfigEntity.SINGLETON_ID)
                .orElseGet(() -> {
                    SiemConfigEntity fresh = new SiemConfigEntity();
                    fresh.setId(SiemConfigEntity.SINGLETON_ID);
                    return fresh;
                });
        entity.setEnabled(enabled);
        entity.setProtocol(protocol != null ? protocol : "WEBHOOK");
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
        entity.setMinSeverity(minSeverity != null ? minSeverity : "HIGH");
        entity.setUpdatedAt(Instant.now());
        return repository.save(entity);
    }

    @Async
    public void exportEvent(CefEvent event) {
        getConfig().ifPresent(config -> {
            if (!config.isEnabled() || config.getEndpoint() == null || config.getEndpoint().isBlank()) {
                return;
            }
            try {
                sendPayload(config.getEndpoint(), storedAuthHeader(config), event.toCefString());
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
            sendPayload(endpoint, authHeader, testEvent.toCefString());
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

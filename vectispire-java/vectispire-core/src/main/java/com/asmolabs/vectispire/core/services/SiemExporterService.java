package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.net.OutboundPolicy;
import com.asmolabs.zanshin.common.domain.siem.CefEvent;
import com.asmolabs.zanshin.common.domain.siem.SecurityEventType;
import com.asmolabs.zanshin.core.persistence.SiemConfigEntity;
import com.asmolabs.zanshin.core.repositories.SiemConfigs;
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

    private static final Logger log = LoggerFactory.getLogger(SiemExporterService.class);
    private final SiemConfigs repository;
    private final OutboundPost outbound;

    public SiemExporterService(SiemConfigs repository, OutboundPost outbound) {
        this.repository = repository;
        this.outbound = outbound;
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
        entity.setAuthHeader(authHeader);
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
                sendPayload(config.getEndpoint(), config.getAuthHeader(), event.toCefString());
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
                    .message("Zanshin SIEM Health Check Ping")
                    .build();
            sendPayload(endpoint, authHeader, testEvent.toCefString());
            return new TestResult(true, "Event delivered successfully", 200);
        } catch (Exception e) {
            return new TestResult(false, "Connection error: " + e.getMessage(), 0);
        }
    }

    private void sendPayload(String endpoint, String authHeader, String cefString) {
        Map<String, String> headers = new HashMap<>();
        if (authHeader != null && !authHeader.isBlank()) {
            headers.put("Authorization", authHeader);
        }
        Map<String, String> payload = Map.of("cef", cefString);
        outbound.postForResponse(endpoint, payload, OutboundPolicy.INTERNAL_ALLOWED, "SIEM export", headers);
    }

    public record TestResult(boolean success, String message, int statusCode) {}
}

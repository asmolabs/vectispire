package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.SiemExporterService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Management API for SIEM & SOC integration configurations.
 */
@RestController
@RequestMapping("/api/v1/siem")
@RequiresSecurityLead
public class SiemController {

    private final SiemExporterService exporterService;
    private final AuditLogService audit;

    public SiemController(SiemExporterService exporterService, AuditLogService audit) {
        this.exporterService = exporterService;
        this.audit = audit;
    }

    public record SiemConfigRequest(
            boolean enabled,
            String protocol,
            String endpoint,
            String authHeader,
            String minSeverity) {}

    public record SiemConfigResponse(
            boolean enabled,
            String protocol,
            String endpoint,
            boolean hasAuthHeader,
            String minSeverity,
            String updatedAt) {}

    public record SiemTestRequest(String endpoint, String authHeader) {}

    @GetMapping("/config")
    public SiemConfigResponse getConfig() {
        return exporterService.getConfig()
                .map(this::toResponse)
                .orElseGet(() -> new SiemConfigResponse(false, "WEBHOOK", null, false, "HIGH", null));
    }

    @PutMapping("/config")
    public SiemConfigResponse updateConfig(
            @RequestBody SiemConfigRequest request,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest httpRequest) {

        SiemConfigEntity saved = exporterService.saveConfig(
                request.enabled(),
                request.protocol(),
                request.endpoint(),
                request.authHeader(),
                request.minSeverity());

        String username = principal != null && principal.user().isPresent()
                ? principal.user().get().getUsername()
                : "system";
        String ip = httpRequest != null ? httpRequest.getRemoteAddr() : null;
        String userAgent = httpRequest != null ? httpRequest.getHeader("User-Agent") : null;

        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                String.valueOf(saved.getId()),
                "SIEM configuration updated (enabled=" + saved.isEnabled() + ", protocol=" + saved.getProtocol() + ")",
                username,
                ip,
                userAgent));

        return toResponse(saved);
    }

    @PostMapping("/test")
    public SiemExporterService.TestResult testConnection(@RequestBody SiemTestRequest request) {
        return exporterService.testConnection(request.endpoint(), request.authHeader());
    }

    private SiemConfigResponse toResponse(SiemConfigEntity entity) {
        return new SiemConfigResponse(
                entity.isEnabled(),
                entity.getProtocol(),
                entity.getEndpoint(),
                entity.getAuthHeader() != null && !entity.getAuthHeader().isBlank(),
                entity.getMinSeverity(),
                entity.getUpdatedAt() != null ? entity.getUpdatedAt().toString() : null);
    }
}

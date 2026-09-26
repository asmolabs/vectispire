package com.asmolabs.vectispire.core.siem.web;

import com.asmolabs.vectispire.core.api.RequestActors;
import com.asmolabs.vectispire.core.api.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.siem.SiemConfigView;
import com.asmolabs.vectispire.core.siem.SiemExporterService;
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
@RequiresGovernanceRead
public class SiemController {

    private final SiemExporterService exporterService;

    public SiemController(SiemExporterService exporterService) {
        this.exporterService = exporterService;
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

    /**
     * @param protocol the transport to test; absent, the stored one — so the button tests what the
     *     export will use, including a protocol changed on screen and not yet saved
     */
    public record SiemTestRequest(String protocol, String endpoint, String authHeader) {}

    @GetMapping("/config")
    public SiemConfigResponse getConfig() {
        return exporterService.getConfig()
                .map(this::toResponse)
                .orElseGet(() -> new SiemConfigResponse(false, "WEBHOOK", null, false, "HIGH", null));
    }

    @RequiresSecurityLead
    @PutMapping("/config")
    public SiemConfigResponse updateConfig(
            @RequestBody SiemConfigRequest request,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest httpRequest) {

        SiemConfigView saved = exporterService.saveConfig(
                request.enabled(),
                request.protocol(),
                request.endpoint(),
                request.authHeader(),
                request.minSeverity(),
                RequestActors.of(principal, httpRequest, "system"));

        return toResponse(saved);
    }

    @RequiresSecurityLead
    @PostMapping("/test")
    public SiemExporterService.TestResult testConnection(@RequestBody SiemTestRequest request) {
        return exporterService.testConnection(request.protocol(), request.endpoint(), request.authHeader());
    }

    private SiemConfigResponse toResponse(SiemConfigView config) {
        return new SiemConfigResponse(
                config.enabled(),
                config.protocol(),
                config.endpoint(),
                config.hasAuthHeader(),
                config.minSeverity(),
                config.updatedAt() != null ? config.updatedAt().toString() : null);
    }
}

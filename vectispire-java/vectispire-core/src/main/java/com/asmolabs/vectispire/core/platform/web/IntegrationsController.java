package com.asmolabs.vectispire.core.platform.web;

import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresPlatformGovernor;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.platform.IntegrationAdministrationService;
import com.asmolabs.vectispire.core.settings.IntegrationView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The integrations' registry (decision 0040): read by every account, switched by the platform governor.
 * In {@code platform} because the registry is the foundation's ({@code settings}), and a foundation module
 * keeps no controller — its routes need {@code access}'s markers, and {@code access} uses the foundation.
 */
@Tag(name = "Integrations", description = "The outside systems this installation may talk to, switched on and off")
@RestController
@RequestMapping("/api/v1/integrations")
public class IntegrationsController {

    private final IntegrationAdministrationService integrations;

    public IntegrationsController(IntegrationAdministrationService integrations) {
        this.integrations = integrations;
    }

    /** @param enabled whether the installation may talk to the integration — required */
    public record IntegrationEnabled(Boolean enabled) {}

    @Operation(summary = "List integrations", description = "Every integration this version knows — forge kinds, "
            + "SIEM transports, AI providers, notification channels, trackers — with whether it is enabled. Any "
            + "account: the screens filter their forms with it. updatedAt and updatedBy are null while no governor "
            + "has switched it; updatedBy is null too for a reader who does not read governance.")
    @GetMapping
    @RequiresAccount
    public List<IntegrationView> list(@AuthenticationPrincipal VectispirePrincipal principal) {
        return integrations.list(principal.requireUser());
    }

    @Operation(summary = "Enable or disable integration", description = "Platform governor only. 404 for a key no "
            + "integration has; 400 without enabled. The same state again changes and records nothing. Audited "
            + "INTEGRATION_ENABLED_CHANGED, and signalled to the SIEM as VECTI-SEC-019. A route of a disabled "
            + "integration answers 409 integration-disabled, naming it in the member integration.")
    @PutMapping("/{key}/enabled")
    @RequiresPlatformGovernor
    public IntegrationView setEnabled(
            @PathVariable String key,
            @RequestBody(required = false) IntegrationEnabled body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return integrations.setEnabled(key, body == null ? null : body.enabled(), principal.requireUser(),
                RequestActors.of(principal, request));
    }
}

package com.asmolabs.vectispire.core.reportplugins.web;

import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.reportplugins.ReportPluginActivationView;
import com.asmolabs.vectispire.core.reportplugins.ReportPluginService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Which report plugins a project may be rendered with (decision 0035 §4).
 *
 * <p><b>The marker is the role; the service is the visibility.</b> Switching one on is the security lead's;
 * reading the list is anybody's who sees the whole project, images included — those who may later ask for a
 * report. Every other caller, and a project that does not exist, gets the same 404.
 */
@Tag(name = "Report plugins", description = "Signed container images turning a project export into one document")
@RestController
@RequestMapping("/api/v1/projects/{projectId}/report-plugins")
public class ProjectReportPluginsController {

    private final ReportPluginService plugins;
    private final VisibilityService visibility;

    public ProjectReportPluginsController(ReportPluginService plugins, VisibilityService visibility) {
        this.plugins = plugins;
        this.visibility = visibility;
    }

    @Operation(summary = "List report plugins switched on for project", description = "For a caller who sees the "
            + "whole project, images included; 404 \"Project not found.\" otherwise, and for a project that does not "
            + "exist.")
    @GetMapping
    @RequiresAccount
    public List<ReportPluginActivationView> list(
            @PathVariable long projectId, @AuthenticationPrincipal VectispirePrincipal principal) {
        return plugins.activations(projectId, allowanceOf(principal));
    }

    @Operation(summary = "Switch report plugin on for project", description = "Security leads who see the whole "
            + "project. 409 report-plugin-not-approved for a plugin with no approved manifest — awaiting approval, or "
            + "withdrawn. Repeating it changes nothing. Audited, and signalled to the SIEM as VECTI-SEC-031.")
    @PutMapping("/{pluginId}")
    @RequiresSecurityLead
    public ReportPluginActivationView activate(
            @PathVariable long projectId,
            @PathVariable String pluginId,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return plugins.activate(projectId, pluginId, allowanceOf(principal), RequestActors.of(principal, request));
    }

    @Operation(summary = "Switch report plugin off for project", description = "404 when it was not on.")
    @DeleteMapping("/{pluginId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @RequiresSecurityLead
    public void deactivate(
            @PathVariable long projectId,
            @PathVariable String pluginId,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        plugins.deactivate(projectId, pluginId, allowanceOf(principal), RequestActors.of(principal, request));
    }

    /** The account's grant intersected with the credential's restriction, with the projects granted as such. */
    private VisibilityService.Allowance allowanceOf(VectispirePrincipal principal) {
        return visibility.allowance(principal.user().orElse(null), principal.credentialRestriction());
    }
}

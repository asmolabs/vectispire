package com.asmolabs.vectispire.core.reportplugins.web;

import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.reportplugins.ReportRunService;
import com.asmolabs.vectispire.core.reportplugins.ReportRunView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * A project's reports (decision 0035 §2): asked of a report plugin switched on for the project, queued, and read
 * back with what came of them. The service refuses the project, checks the role and audits; this maps the request.
 *
 * <p>{@code @RequiresAccount} rather than a write marker: the auditor requests reports too (answer 4), and the one
 * role left out — the platform governor — is refused by the service, after the project. No integration key: a
 * report is somebody's request, and the export is built for them. No route serves a document yet: lot R4 checks,
 * signs and serves the output.
 */
@Tag(name = "Report plugins", description = "Signed container images turning a project export into one document")
@RestController
@RequestMapping("/api/v1/projects/{projectId}/reports")
public class ProjectReportsController {

    private final ReportRunService reports;
    private final VisibilityService visibility;

    public ProjectReportsController(ReportRunService reports, VisibilityService visibility) {
        this.reports = reports;
        this.visibility = visibility;
    }

    /** @param pluginId the report plugin to render the project with — one switched on for it */
    public record ReportRequest(String pluginId) {}

    @Operation(summary = "Request report", description = "Queues a report of the project by a report plugin switched "
            + "on for it, for the control plane's executor: 202 with the run, pending. The executor builds the project's "
            + "export for the requester at the claim and runs the plugin's approved manifest — signer verified, no "
            + "network, the export read-only, the output bounded. For write accounts and auditors who see the whole "
            + "project, images included: 404 \"Project not found.\" otherwise; 403 for the platform governor; 404 for a "
            + "plugin not switched on for the project; 409 report-plugin-disabled, report-plugin-not-approved, "
            + "report-executor-unavailable (the built-in worker is switched off: this version runs report plugins on "
            + "the control plane only), report-run-in-progress (one run of a plugin per project at a time). Audited "
            + "REPORT_REQUESTED; the export handed to the plugin is audited PROJECT_EXPORTED and signalled "
            + "VECTI-SEC-032, a refused run REPORT_REFUSED and VECTI-SEC-033.")
    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    @RequiresAccount
    public ReportRunView request(
            @PathVariable long projectId,
            @RequestBody ReportRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return reports.request(projectId, body == null ? null : body.pluginId(), principal.requireUser(),
                allowanceOf(principal), request.getHeader(HttpHeaders.ACCEPT_LANGUAGE),
                RequestActors.of(principal, request));
    }

    @Operation(summary = "List project reports", description = "The project's report runs, newest first, the latest "
            + "200: state (pending, running, produced, failed, refused), the reason and detail of a run that did not "
            + "produce, the manifest, image, signer and export it ran with, the output's size and SHA-256. For a caller "
            + "who sees the whole project; 404 \"Project not found.\" otherwise.")
    @GetMapping
    @RequiresAccount
    public List<ReportRunView> list(
            @PathVariable long projectId, @AuthenticationPrincipal VectispirePrincipal principal) {
        return reports.runs(projectId, allowanceOf(principal));
    }

    @Operation(summary = "Get project report", description = "One report run of the project. 404 \"Project not "
            + "found.\" for a project not seen whole, then 404 for a run that is not the project's.")
    @GetMapping("/{runId}")
    @RequiresAccount
    public ReportRunView get(
            @PathVariable long projectId,
            @PathVariable long runId,
            @AuthenticationPrincipal VectispirePrincipal principal) {
        return reports.run(projectId, runId, allowanceOf(principal));
    }

    /** The account's grant intersected with the credential's restriction, with the projects granted as such. */
    private VisibilityService.Allowance allowanceOf(VectispirePrincipal principal) {
        return visibility.allowance(principal.user().orElse(null), principal.credentialRestriction());
    }
}

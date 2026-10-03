package com.asmolabs.vectispire.core.reportplugins.web;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.access.web.security.RequiresPlatformGovernor;
import com.asmolabs.vectispire.core.access.web.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.reportplugins.ReportPluginService;
import com.asmolabs.vectispire.core.reportplugins.ReportPluginView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * The report plugins' registry (decision 0035 §4). The service decides — four-eyes, the states, the audit —
 * and this maps the requests.
 *
 * <p><b>Reading it is governance reading</b>, not anybody's: a report plugin's manifests, their approvals and
 * their withdrawals are how the platform decides which code may produce documents under its key. Writing it
 * is the platform governor's; approving a digest is any governance writer's but its registrant's, which the
 * service checks. There is no delete: an id names every document the plugin produced.
 */
@Tag(name = "Report plugins", description = "Signed container images turning a project export into one document")
@RestController
@RequestMapping("/api/v1/report-plugins")
public class ReportPluginsController {

    private final ReportPluginService plugins;

    public ReportPluginsController(ReportPluginService plugins) {
        this.plugins = plugins;
    }

    /** @param enabled false stops every activation from rendering, without forgetting them */
    public record ReportPluginEnabled(Boolean enabled) {}

    /** @param justification what was wrong with the manifest, 20 to 500 characters — required */
    public record WithdrawalRequest(String justification) {}

    @Operation(summary = "List report plugins", description = "Every registered report plugin, with the manifest "
            + "history of each: status, approval, withdrawal.")
    @GetMapping
    @RequiresGovernanceRead
    public List<ReportPluginView> list() {
        return plugins.list();
    }

    @Operation(summary = "Read report plugin", description = "404 when no plugin has that id.")
    @GetMapping("/{id}")
    @RequiresGovernanceRead
    public ReportPluginView get(@PathVariable String id) {
        return plugins.get(id);
    }

    @Operation(summary = "Register report plugin", description = "Platform governor only. The image is pinned by "
            + "digest, the signer is required, the output's media type is one of the closed list, and the export "
            + "major one this installation produces; 400 otherwise. With four-eyes on the manifest waits for a "
            + "second person's approval; with it off it serves at once. 409 report-plugin-id-taken when the id is "
            + "taken — ids are never reused. Audited, and signalled to the SIEM as VECTI-SEC-031.")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPlatformGovernor
    public ReportPluginView register(
            @RequestBody ReportPluginManifest manifest,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return plugins.register(manifest, principal.requireUser(), RequestActors.of(principal, request));
    }

    @Operation(summary = "Update report plugin", description = "Platform governor only. A new manifest under the "
            + "same id: with four-eyes on it waits for approval and the approved one keeps serving; a manifest "
            + "approved before serves at once; 409 report-plugin-withdrawn for a withdrawn one. The same manifest "
            + "again changes nothing.")
    @PutMapping("/{id}")
    @RequiresPlatformGovernor
    public ReportPluginView update(
            @PathVariable String id,
            @RequestBody ReportPluginManifest manifest,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return plugins.update(id, manifest, principal.requireUser(), RequestActors.of(principal, request));
    }

    @Operation(summary = "Approve report plugin manifest", description = "Governance writers. Approves the plugin's "
            + "pending manifest digest: its runs use it from now on. With four-eyes on, 409 report-plugin-four-eyes "
            + "for the account that registered it; 409 report-plugin-not-pending for a digest not awaiting "
            + "approval; 404 for a plugin or digest that does not exist.")
    @PostMapping("/{id}/manifests/{digest}/approval")
    @RequiresSecurityLead
    public ReportPluginView approve(
            @PathVariable String id,
            @PathVariable String digest,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return plugins.approve(id, digest, principal.requireUser(), RequestActors.of(principal, request));
    }

    @Operation(summary = "Withdraw report plugin manifest", description = "Platform governor only. The digest never "
            + "runs again and cannot be registered again; the documents it produced stay stored, served as "
            + "withdrawn. The justification is required, 20 to 500 characters; 400 without it; 409 "
            + "report-plugin-withdrawn when it already was.")
    @PostMapping("/{id}/manifests/{digest}/withdrawal")
    @RequiresPlatformGovernor
    public ReportPluginView withdraw(
            @PathVariable String id,
            @PathVariable String digest,
            @RequestBody(required = false) WithdrawalRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return plugins.withdraw(id, digest, body == null ? null : body.justification(), principal.requireUser(),
                RequestActors.of(principal, request));
    }

    @Operation(summary = "Enable or disable report plugin", description = "Platform governor only. Disabling stops "
            + "every activation from rendering without forgetting them.")
    @PutMapping("/{id}/enabled")
    @RequiresPlatformGovernor
    public ReportPluginView setEnabled(
            @PathVariable String id,
            @RequestBody(required = false) ReportPluginEnabled body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        if (body == null || body.enabled() == null) {
            throw new InvalidInputException("Say whether the report plugin is enabled.");
        }
        return plugins.setEnabled(id, body.enabled(), principal.requireUser(), RequestActors.of(principal, request));
    }
}

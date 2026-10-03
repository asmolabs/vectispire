package com.asmolabs.vectispire.core.reportplugins.web;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.reportplugins.ProjectExportDownload;
import com.asmolabs.vectispire.core.reportplugins.ProjectExportService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * A project's export and its schema (decision 0035 §1). The service refuses the project, checks the role
 * and audits; this maps the request and the response.
 *
 * <p>{@code @RequiresAccount} rather than {@code @RequiresWriteAccount}: the auditor takes an export too
 * (answer 4), and the one role left out — the platform governor — is refused by the service, after the
 * project, so that the refusal says nothing of whether it exists.
 */
@RestController
public class ProjectExportController {

    private static final MediaType ZIP = MediaType.parseMediaType("application/zip");

    /** RFC 9727's type for a JSON Schema document. */
    private static final MediaType SCHEMA_JSON = MediaType.parseMediaType("application/schema+json");

    private final ProjectExportService exports;
    private final VisibilityService visibility;

    public ProjectExportController(ProjectExportService exports, VisibilityService visibility) {
        this.exports = exports;
        this.visibility = visibility;
    }

    @Operation(summary = "Download project export", description = "A zip: export.json — the project as the "
            + "vectispire-project-export schema describes it (GET /api/v1/schemas/project-export/1): its targets, "
            + "each one's newest completed scan and last gate verdict, every issue not resolved with its triage, "
            + "the counts per type, severity, state and triage status, the consolidated components, the compliance "
            + "state and the checklist statements — and export.json.sig, its detached signature by the platform's "
            + "key, to check with cosign verify-blob --key against /api/v1/crypto/public-key.pub. No source, no "
            + "secret value, no credential, no e-mail address: people by display name, evidence by digest. "
            + "Always an attachment. For write accounts and auditors who see the whole project, images included; "
            + "accepts an integration key with the export scope. 404 \"Project not found.\" for a project absent, "
            + "hidden or seen only in part — a key restricted to one repository included; 403 for the platform "
            + "governor; 409 project-export-too-large over 100,000 issues or components or 64 MiB of JSON, with "
            + "part, found and limit — refused, never cut short. Audited PROJECT_EXPORTED, signalled VECTI-SEC-032.")
    @ApiResponse(responseCode = "200", description = "The export, application/zip",
            content = @Content(mediaType = "application/zip", schema = @Schema(type = "string", format = "binary")))
    @GetMapping(value = "/api/v1/projects/{projectId}/export", produces = "application/zip")
    @RequiresAccount
    @AcceptsApiKey(ApiKeyScope.EXPORT)
    public ResponseEntity<byte[]> export(
            @PathVariable long projectId,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        ProjectExportDownload export = exports.export(projectId, principal.requireUser(), allowanceOf(principal),
                request.getHeader(HttpHeaders.ACCEPT_LANGUAGE), RequestActors.of(principal, request));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(export.fileName(), StandardCharsets.UTF_8).build().toString())
                .header("X-Content-Type-Options", "nosniff")
                .contentType(ZIP)
                .body(export.content());
    }

    /**
     * The account's grant intersected with the credential's restriction, with the projects granted as such:
     * a key narrowed to one repository never sees a whole project, and the service refuses it as absent.
     */
    private VisibilityService.Allowance allowanceOf(VectispirePrincipal principal) {
        return visibility.allowance(principal.user().orElse(null), principal.credentialRestriction());
    }

    @Operation(summary = "Project export schema", description = "The JSON Schema (draft 2020-12) of one major of "
            + "vectispire-project-export, as this installation produces it — what a report plugin's author writes "
            + "against. A minor adds optional fields and never removes or changes one: a reader ignores what it does "
            + "not know. 404 for a major this installation does not produce.")
    @ApiResponse(responseCode = "200", description = "The schema, application/schema+json",
            content = @Content(mediaType = "application/schema+json", schema = @Schema(type = "string", format = "binary")))
    @GetMapping(value = "/api/v1/schemas/project-export/{major}", produces = "application/schema+json")
    @RequiresAccount
    @AcceptsApiKey(ApiKeyScope.EXPORT)
    public ResponseEntity<byte[]> schema(@PathVariable int major) {
        return ResponseEntity.ok()
                .header("X-Content-Type-Options", "nosniff")
                .contentType(SCHEMA_JSON)
                .body(exports.schema(major));
    }
}

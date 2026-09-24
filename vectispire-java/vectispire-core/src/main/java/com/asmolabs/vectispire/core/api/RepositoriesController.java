package com.asmolabs.vectispire.core.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.services.RepositoryAdministrationService;
import com.asmolabs.vectispire.core.services.RepositoryAdministrationService.Changes;
import com.asmolabs.vectispire.core.services.RepositoryAdministrationService.Listed;
import com.asmolabs.vectispire.core.services.VisibilityService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** The repositories under watch, and triggering their scans. */
@Tag(name = "Repositories", description = "Target repository inventory, Git synchronization and scan triggers")
@RestController
@RequestMapping("/api/v1/repositories")
// Listing is readable by any account; creating, scanning and deleting are administrators' —
// a scan costs machine time and the queue is shared. The method's marker wins over the class's.
@RequiresAccount
public class RepositoriesController {

    private final RepositoryAdministrationService inventory;
    private final VisibilityService visibility;

    public RepositoriesController(RepositoryAdministrationService inventory, VisibilityService visibility) {
        this.inventory = inventory;
        this.visibility = visibility;
    }

    public record LastScan(Long id, String status, Instant createdAt, String error) {}

    public record RepositorySummary(
            Long id,
            String url,
            String branch,
            String name,
            String subPath,
            String displayName,
            Integer scanIntervalMinutes,
            String scanCron,
            String requiredAgentLabel,
            UUID sshKeyId,
            Instant lastScheduledScanAt,
            LastScan lastScan,
            long openIssues,
            String tier) {}

    /** The names the Angular client sends. See {@code ClientContractTest} for why they differ. */
    public record RepositoryCreateRequest(
            String url,
            String branch,
            String name,
            String subPath,
            Integer scanIntervalMinutes,
            String scanCron,
            @JsonProperty("required_agent_label") String requiredAgentLabel,
            // **A string and not a `UUID`, for the same reason the fields above are strings.** The
            // update path reads absent as "leave alone", so a typed `UUID` gives the operator no
            // way to say "no key any more" — null would be indistinguishable from "unchanged", and
            // the form would show the key detached while the next clone still used it. The empty
            // string is the explicit clear; a malformed one is a 400 rather than a silent no-op.
            String sshKeyId,
            String tier) {}

    public record QueuedScan(Long id, String status) {}

    /** The list, with each target's latest scan and how many issues are waiting on it. */
    @Operation(summary = "List repositories", description = "Returns all git repositories monitored by Vectispire visible to the caller.")
    @ApiResponse(responseCode = "200", description = "Repositories list retrieved successfully")
    @GetMapping
    public List<RepositorySummary> list(@AuthenticationPrincipal VectispirePrincipal principal) {
        return inventory.list(allowed(principal)).stream()
                .map(RepositoriesController::summaryOf)
                .toList();
    }

    @Operation(summary = "Create repository", description = "Registers a new Git repository for automated security scanning.")
    @ApiResponse(responseCode = "200", description = "Repository registered successfully")
    @RequiresAdministrator
    @PostMapping
    public RepositorySummary create(
            @RequestBody RepositoryCreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        RepositoryEntity saved = inventory.create(changesOf(body), RequestActors.of(principal, request));
        return summaryOf(inventory.listed(allowed(principal), saved.getId()).orElseThrow());
    }

    /**
     * Changes a monitored repository.
     *
     * <p><b>Absent means unchanged, not cleared.</b> A {@code null} field is left alone and an
     * empty string clears it: with the opposite convention, a screen sending only the two fields
     * it edits would silently erase the SSH key, the schedule and the agent label. That mistake
     * is invisible until the next scan waits for an agent nobody requires any more.
     *
     * <p><b>Changing the URL keeps the issues.</b> The fingerprint does not include the
     * repository, so the backlog attached to this row survives and now describes a different
     * codebase. That is the right behaviour for the ordinary case — a repository that moved host
     * — and the wrong one for pointing an existing row at an unrelated project. The audit entry
     * records both URLs so the surprise has an explanation.
     */
    @Operation(summary = "Update repository", description = "Updates configuration, schedule or credentials of a monitored repository.")
    @ApiResponse(responseCode = "200", description = "Repository updated successfully")
    @RequiresAdministrator
    @PatchMapping("/{id}")
    public RepositorySummary update(
            @Parameter(description = "Repository identifier", required = true) @PathVariable long id,
            @RequestBody RepositoryCreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        RepositoryEntity saved =
                inventory.update(id, changesOf(body), allowed(principal), RequestActors.of(principal, request));
        return summaryOf(inventory.listed(allowed(principal), saved.getId()).orElseThrow());
    }

    /**
     * Queues a scan of this repository.
     *
     * <p>Administrators only: a scan costs machine time and network, and the queue is shared.
     */
    @Operation(summary = "Trigger repository scan", description = "Enqueues an immediate full security scan (SBOM, CVE, Secrets, SAST, IaC, APIs).")
    @ApiResponse(responseCode = "200", description = "Scan queued successfully")
    @RequiresAdministrator
    @PostMapping("/{id}/scan")
    public QueuedScan triggerScan(
            @Parameter(description = "Repository identifier", required = true) @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        RepositoryAdministrationService.Triggered triggered = inventory.trigger(id, RequestActors.of(principal, request));
        return new QueuedScan(triggered.scan().getId(), triggered.scan().getStatus());
    }

    @Operation(summary = "Delete repository", description = "Removes repository and cascades deletion of its issues, findings and history.")
    @ApiResponse(responseCode = "204", description = "Repository deleted successfully")
    @RequiresAdministrator
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @Parameter(description = "Repository identifier", required = true) @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        inventory.delete(id, RequestActors.of(principal, request));
    }

    private Visibility allowed(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }

    private static RepositorySummary summaryOf(Listed listed) {
        RepositoryEntity repository = listed.repository();
        return new RepositorySummary(
                repository.getId(),
                RepositoryUrl.redact(repository.getUrl()),
                repository.getBranch(),
                repository.getName(),
                repository.getSubPath(),
                displayName(repository),
                repository.getScanIntervalMinutes(),
                repository.getScanCron(),
                repository.getRequiredAgentLabel(),
                repository.getSshKeyId(),
                repository.getLastScheduledScanAt(),
                listed.latestScan()
                        .map(scan -> new LastScan(scan.id(), scan.status(), scan.createdAt(), scan.error()))
                        .orElse(null),
                listed.openIssues(),
                repository.getTier());
    }

    private static Changes changesOf(RepositoryCreateRequest body) {
        return new Changes(
                body.url(),
                body.branch(),
                body.name(),
                body.subPath(),
                body.scanIntervalMinutes(),
                body.scanCron(),
                body.requiredAgentLabel(),
                body.sshKeyId(),
                body.tier());
    }

    /**
     * What the screen calls it, through the domain's rule rather than a copy of it.
     *
     * <p><b>This method used to be that copy, and the two had already diverged.</b>
     * {@link RepositoryUrl#displayName} falls back to the short form — {@code org/project} —
     * where this returned the whole URL; it was tested, and called by nothing. The backlog's
     * new target column forced the question, because a third rule would have had the same
     * repository named two different things on two screens.
     *
     * <p>The visible change: a repository with no operator-chosen name now reads
     * {@code org/project} instead of {@code https://github.com/org/project.git}. That is also
     * what makes it fit in a table column.
     */
    private static String displayName(RepositoryEntity repository) {
        return RepositoryUrl.displayName(repository.getName(), repository.getUrl());
    }
}

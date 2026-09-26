package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.targets.ImageReference;
import com.asmolabs.vectispire.core.api.RepositoriesController.LastScan;
import com.asmolabs.vectispire.core.api.RepositoriesController.QueuedScan;
import com.asmolabs.vectispire.core.api.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.services.targets.ContainerAdministrationService.Changes;
import com.asmolabs.vectispire.core.services.targets.ContainerAdministrationService.Listed;
import com.asmolabs.vectispire.core.services.targets.ContainerAdministrationService;
import com.asmolabs.vectispire.core.services.access.VisibilityService;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** The container images under watch, and triggering their scans. */
@RestController
@RequestMapping("/api/v1/containers")
// Listing is readable by any account; creating, scanning and deleting are administrators' —
// a scan costs machine time and the queue is shared. The method's marker wins over the class's.
@RequiresAccount
public class ContainersController {

    private final ContainerAdministrationService inventory;
    private final VisibilityService visibility;

    public ContainersController(ContainerAdministrationService inventory, VisibilityService visibility) {
        this.inventory = inventory;
        this.visibility = visibility;
    }

    public record ContainerSummary(
            Long id,
            String registry,
            String imageName,
            String tag,
            String reference,
            String displayName,
            Integer scanIntervalMinutes,
            String scanCron,
            String requiredAgentLabel,
            Instant lastScheduledScanAt,
            LastScan lastScan,
            long openIssues,
            String tier) {}

    /** The names the Angular client sends. See {@code ClientContractTest} for why they differ. */
    public record ContainerCreateRequest(
            String registry,
            @JsonProperty("image_name") String imageName,
            String tag,
            Integer scanIntervalMinutes,
            String scanCron,
            @JsonProperty("required_agent_label") String requiredAgentLabel,
            String tier) {}

    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping
    public List<ContainerSummary> list(@AuthenticationPrincipal VectispirePrincipal principal) {
        return inventory.list(allowed(principal)).stream()
                .map(ContainersController::summaryOf)
                .toList();
    }

    @RequiresAdministrator
    @PostMapping
    public ContainerSummary create(
            @RequestBody ContainerCreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        ContainerEntity saved = inventory.create(changesOf(body), RequestActors.of(principal, request));
        return summaryOf(inventory.listed(allowed(principal), saved.getId()).orElseThrow());
    }

    /**
     * Changes a monitored image.
     *
     * <p>There was no such route: create, scan and delete were the whole surface, so correcting a
     * cron expression on an image meant deleting the row — and its scan history and its triaged
     * backlog with it. Offering the schedule field with no way to fix it is worse than not
     * offering it.
     *
     * <p><b>Absent means unchanged, not cleared.</b> A {@code null} field is left alone and an
     * empty string clears it, exactly as on {@link RepositoriesController#update}: with the
     * opposite convention, a screen sending only the two fields it edits would silently erase the
     * schedule and the agent label, and nothing would say so until a scan waited for an agent
     * nobody requires any more.
     *
     * <p><b>The interval is the one field that cannot be cleared by emptiness</b>, because it is
     * an {@code Integer} and not a string: {@code null} is already spoken for as "leave alone", so
     * a caller switching a rescan off has to send {@code 0} — which is what {@code
     * Schedules.intervalDue} reads as manual-only anyway. {@code scanCron} has no such problem,
     * the empty string being distinguishable from absent, and does clear the expression. That
     * asymmetry is the frontend's to honour: it sends zero, not nothing.
     *
     * <p><b>Changing the reference keeps the issues.</b> The fingerprint does not include the
     * image, so the backlog attached to this row survives and now describes a different image —
     * right for a tag that moved, wrong for repointing a row at an unrelated image. The audit
     * entry records both references so the surprise has an explanation.
     */
    @RequiresAdministrator
    @PatchMapping("/{id}")
    public ContainerSummary update(
            @PathVariable long id,
            @RequestBody ContainerCreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        ContainerEntity saved =
                inventory.update(id, changesOf(body), allowed(principal), RequestActors.of(principal, request));
        return summaryOf(inventory.listed(allowed(principal), saved.getId()).orElseThrow());
    }

    @RequiresAdministrator
    @AcceptsApiKey(ApiKeyScope.SCAN)
    @PostMapping("/{id}/scan")
    public QueuedScan triggerScan(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        ContainerAdministrationService.Triggered triggered = inventory.trigger(id, allowed(principal), RequestActors.of(principal, request));
        return new QueuedScan(triggered.scan().getId(), triggered.scan().getStatus());
    }

    @RequiresAdministrator
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        inventory.delete(id, RequestActors.of(principal, request));
    }

    private Visibility allowed(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }

    private static ContainerSummary summaryOf(Listed listed) {
        ContainerEntity container = listed.container();
        ImageReference reference = referenceOf(container);
        return new ContainerSummary(
                container.getId(),
                container.getRegistry(),
                container.getImageName(),
                container.getTag(),
                reference.format(),
                reference.displayName(),
                container.getScanIntervalMinutes(),
                container.getScanCron(),
                container.getRequiredAgentLabel(),
                container.getLastScheduledScanAt(),
                listed.latestScan()
                        .map(scan -> new LastScan(scan.id(), scan.status(), scan.createdAt(), scan.error()))
                        .orElse(null),
                listed.openIssues(),
                container.getTier());
    }

    private static Changes changesOf(ContainerCreateRequest body) {
        return new Changes(
                body.registry(),
                body.imageName(),
                body.tag(),
                body.scanIntervalMinutes(),
                body.scanCron(),
                body.requiredAgentLabel(),
                body.tier());
    }

    private static ImageReference referenceOf(ContainerEntity container) {
        return ContainerAdministrationService.referenceOf(container);
    }
}

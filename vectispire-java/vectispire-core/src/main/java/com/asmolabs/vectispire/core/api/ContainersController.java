package com.asmolabs.vectispire.core.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.targets.ImageReference;
import com.asmolabs.vectispire.common.domain.targets.AssetTier;
import com.asmolabs.vectispire.core.api.RepositoriesController.LastScan;
import com.asmolabs.vectispire.core.api.RepositoriesController.QueuedScan;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.core.repositories.TeamTargets;
import com.asmolabs.vectispire.core.repositories.UserTargets;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import com.asmolabs.vectispire.core.services.CronExpressions;
import com.asmolabs.vectispire.core.services.ScanTriggerService;
import com.asmolabs.vectispire.core.services.TargetDeletionService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import org.springframework.http.HttpStatus;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresAdministrator;
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

    private final Containers containers;
    private final Scans scans;
    private final Issues issues;
    private final ScanTriggerService trigger;
    private final AuditLogService audit;
    private final VisibilityService visibility;

    private final UserTargets userTargets;
    private final TeamTargets teamTargets;
    private final TargetDeletionService targetDeletion;

    public ContainersController(
            Containers containers, Scans scans, Issues issues, ScanTriggerService trigger, AuditLogService audit,
            VisibilityService visibility,
            UserTargets userTargets,
            TeamTargets teamTargets,
            TargetDeletionService targetDeletion) {
        this.userTargets = userTargets;
        this.teamTargets = teamTargets;
        this.containers = containers;
        this.scans = scans;
        this.issues = issues;
        this.trigger = trigger;
        this.audit = audit;
        this.visibility = visibility;
        this.targetDeletion = targetDeletion;
    }

    public record Summary(
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
    public record CreateRequest(
            String registry,
            @JsonProperty("image_name") String imageName,
            String tag,
            Integer scanIntervalMinutes,
            String scanCron,
            @JsonProperty("required_agent_label") String requiredAgentLabel,
            String tier) {}

    @GetMapping
    public List<Summary> list(@AuthenticationPrincipal VectispirePrincipal principal) {
        Visibility allowed = visibility.of(
                principal.user().orElse(null), principal.credentialRestriction());
        Map<Long, LastScan> latest = latestScans();
        Map<Long, Long> open = openIssueCounts();

        return containers.findAll().stream()
                .filter(container -> allowed.permits(new ScanTarget.Container(container.getId())))
                .map(container -> {
                    ImageReference reference = referenceOf(container);
                    return new Summary(
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
                            latest.get(container.getId()),
                            open.getOrDefault(container.getId(), 0L),
                            container.getTier());
                })
                .toList();
    }

    @RequiresAdministrator
    @PostMapping
    public Summary create(
            @RequestBody CreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        ImageReference reference = new ImageReference(
                optional(body.registry()),
                trim(body.imageName()),
                trim(body.tag()).isEmpty() ? "latest" : trim(body.tag()));
        // Validated at the entry point, like a repository URL: a reference reaching a `docker
        // pull` unchecked is not a typo, it is whatever the operator's daemon will fetch.
        reference.validate().ifPresent(message -> {
            throw new IllegalArgumentException(message);
        });

        ContainerEntity container = new ContainerEntity();
        container.setRegistry(reference.registry());
        container.setImageName(reference.imageName());
        container.setTag(reference.tag());
        container.setScanIntervalMinutes(body.scanIntervalMinutes());
        container.setScanCron(validatedCron(body.scanCron()));
        container.setRequiredAgentLabel(AgentLabels.normalizeRequirement(body.requiredAgentLabel()).orElse(null));
        container.setTier(body.tier() != null ? AssetTier.fromString(body.tier()).name() : "TIER_2_BUSINESS_OPERATIONAL");

        ContainerEntity saved = containers.save(container);
        record(principal, request, AuditOperation.SETTING_UPDATED, saved.getId(),
                "Image added: " + referenceOf(saved).format());
        return list(principal).stream()
                .filter(summary -> summary.id().equals(saved.getId()))
                .findFirst()
                .orElseThrow();
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
    public Summary update(
            @PathVariable long id,
            @RequestBody CreateRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        ContainerEntity container = containers
                .findById(id)
                .orElseThrow(() -> new NoSuchElementException("No image with id " + id + "."));
        Visibilities.requireVisible(
                new ScanTarget.Container(id),
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));

        String previousReference = referenceOf(container).format();

        // Validated as a whole and not field by field: a registry, a name and a tag are only
        // legal together, and a reference reaching a `docker pull` unchecked is whatever the
        // operator's daemon will fetch — as true of a row edited later as of a row added.
        ImageReference reference = new ImageReference(
                body.registry() != null ? optional(body.registry()) : container.getRegistry(),
                body.imageName() != null ? trim(body.imageName()) : container.getImageName(),
                body.tag() != null ? (trim(body.tag()).isEmpty() ? "latest" : trim(body.tag())) : container.getTag());
        reference.validate().ifPresent(message -> {
            throw new IllegalArgumentException(message);
        });
        container.setRegistry(reference.registry());
        container.setImageName(reference.imageName());
        container.setTag(reference.tag());

        if (body.scanIntervalMinutes() != null) {
            container.setScanIntervalMinutes(body.scanIntervalMinutes());
        }
        if (body.scanCron() != null) {
            container.setScanCron(validatedCron(body.scanCron()));
        }
        if (body.requiredAgentLabel() != null) {
            // Normalized on update as on create: "Production" here and "production" on the agent
            // would never meet, and the scan would wait for an agent that is present.
            container.setRequiredAgentLabel(
                    AgentLabels.normalizeRequirement(body.requiredAgentLabel()).orElse(null));
        }
        if (body.tier() != null) {
            container.setTier(AssetTier.fromString(body.tier()).name());
        }

        ContainerEntity saved = containers.save(container);
        String moved = referenceOf(saved).format().equals(previousReference) ? "" : " (was " + previousReference + ")";
        record(principal, request, AuditOperation.SETTING_UPDATED, saved.getId(),
                "Image updated: " + referenceOf(saved).format() + moved);

        return list(principal).stream()
                .filter(summary -> summary.id().equals(saved.getId()))
                .findFirst()
                .orElseThrow();
    }

    @RequiresAdministrator
    @PostMapping("/{id}/scan")
    public QueuedScan triggerScan(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        ContainerEntity container = containers.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Image not found."));

        ScanEntity scan = trigger.trigger(container);
        record(principal, request, AuditOperation.SCAN_TRIGGERED, scan.getId(),
                "Scan requested: " + referenceOf(container).format());
        return new QueuedScan(scan.getId(), scan.getStatus());
    }

    @RequiresAdministrator
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        ContainerEntity container = containers.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Image not found."));

        targetDeletion.deleteContainer(id);
        record(principal, request, AuditOperation.SETTING_UPDATED, id,
                "Image deleted: " + referenceOf(container).format());
    }

    private Map<Long, LastScan> latestScans() {
        Map<Long, LastScan> latest = new HashMap<>();
        for (Object[] row : scans.findLatestPerContainer()) {
            latest.put(
                    ((Number) row[0]).longValue(),
                    new LastScan(((Number) row[1]).longValue(), (String) row[2], (Instant) row[3], (String) row[4]));
        }
        return latest;
    }

    private Map<Long, Long> openIssueCounts() {
        Map<Long, Long> counts = new HashMap<>();
        for (Object[] row : issues.countOpenByContainer(IssueState.OPEN.wireName())) {
            counts.put(((Number) row[0]).longValue(), ((Number) row[1]).longValue());
        }
        return counts;
    }

    private void record(
            VectispirePrincipal principal,
            HttpServletRequest request,
            AuditOperation operation,
            long resourceId,
            String description) {
        audit.record(new AuditLogService.Record(
                operation,
                String.valueOf(resourceId),
                description,
                principal.user().map(user -> user.getUsername()).orElse(null),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));
    }

    private static ImageReference referenceOf(ContainerEntity container) {
        return new ImageReference(container.getRegistry(), container.getImageName(), container.getTag());
    }

    /**
     * A valid cron expression, {@code null}, or a 400 the operator can read.
     *
     * <p>The same wording as the repository route's: the two dialogs put the server's message
     * straight on screen, and an operator who learned the expected format on one screen should
     * not have to learn it again on the other.
     */
    private static String validatedCron(String expression) {
        String trimmed = trim(expression);
        if (trimmed.isEmpty()) {
            return null;
        }
        if (!CronExpressions.isValid(trimmed)) {
            throw new IllegalArgumentException(
                    "Unusable cron expression: \"" + trimmed + "\". Expected five fields, for example "
                            + "\"0 2 * * *\" (every day at 02:00) or \"0 */6 * * *\" (every six hours).");
        }
        return trimmed;
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }

    private static String optional(String value) {
        String trimmed = trim(value);
        return trimmed.isEmpty() ? null : trimmed;
    }
}

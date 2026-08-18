package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.agents.AgentLabels;
import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.targets.ImageReference;
import com.asmolabs.zanshin.core.api.RepositoriesController.LastScan;
import com.asmolabs.zanshin.core.api.RepositoriesController.QueuedScan;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.ContainerEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Containers;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.Scans;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.CronExpressions;
import com.asmolabs.zanshin.core.services.ScanTriggerService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** The container images under watch, and triggering their scans. */
@RestController
@RequestMapping("/api/v1/containers")
public class ContainersController {

    private final Containers containers;
    private final Scans scans;
    private final Issues issues;
    private final ScanTriggerService trigger;
    private final AuditLogService audit;

    public ContainersController(
            Containers containers, Scans scans, Issues issues, ScanTriggerService trigger, AuditLogService audit) {
        this.containers = containers;
        this.scans = scans;
        this.issues = issues;
        this.trigger = trigger;
        this.audit = audit;
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
            long openIssues) {}

    public record CreateRequest(
            String registry,
            String imageName,
            String tag,
            Integer scanIntervalMinutes,
            String scanCron,
            String requiredAgentLabel) {}

    @GetMapping
    public List<Summary> list() {
        Map<Long, LastScan> latest = latestScans();
        Map<Long, Long> open = openIssueCounts();

        return containers.findAll().stream()
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
                            open.getOrDefault(container.getId(), 0L));
                })
                .toList();
    }

    @PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN')")
    @PostMapping
    public Summary create(
            @RequestBody CreateRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
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

        ContainerEntity saved = containers.save(container);
        record(principal, request, AuditOperation.SETTING_UPDATED, saved.getId(),
                "Image added: " + referenceOf(saved).format());
        return list().stream()
                .filter(summary -> summary.id().equals(saved.getId()))
                .findFirst()
                .orElseThrow();
    }

    @PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN')")
    @PostMapping("/{id}/scan")
    public QueuedScan triggerScan(
            @PathVariable long id,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        ContainerEntity container = containers.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Image not found."));

        ScanEntity scan = trigger.trigger(container);
        record(principal, request, AuditOperation.SCAN_TRIGGERED, scan.getId(),
                "Scan requested: " + referenceOf(container).format());
        return new QueuedScan(scan.getId(), scan.getStatus());
    }

    @PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN')")
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        ContainerEntity container = containers.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Image not found."));

        containers.deleteById(id);
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
            ZanshinPrincipal principal,
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

    private static String validatedCron(String expression) {
        String trimmed = trim(expression);
        if (trimmed.isEmpty()) {
            return null;
        }
        if (!CronExpressions.isValid(trimmed)) {
            throw new IllegalArgumentException("Unusable cron expression: \"" + trimmed + "\".");
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

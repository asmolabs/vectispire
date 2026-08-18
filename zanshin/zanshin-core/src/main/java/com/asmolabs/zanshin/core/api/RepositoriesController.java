package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.agents.AgentLabels;
import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.targets.RepositoryUrl;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
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
import java.util.UUID;
import org.springframework.http.HttpStatus;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.api.security.RequiresAdministrator;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** The repositories under watch, and triggering their scans. */
@RestController
@RequestMapping("/api/v1/repositories")
// Listing is readable by any account; creating, scanning and deleting are administrators' —
// a scan costs machine time and the queue is shared. The method's marker wins over the class's.
@RequiresAccount
public class RepositoriesController {

    private final GitRepositories repositories;
    private final Scans scans;
    private final Issues issues;
    private final ScanTriggerService trigger;
    private final AuditLogService audit;

    public RepositoriesController(
            GitRepositories repositories,
            Scans scans,
            Issues issues,
            ScanTriggerService trigger,
            AuditLogService audit) {
        this.repositories = repositories;
        this.scans = scans;
        this.issues = issues;
        this.trigger = trigger;
        this.audit = audit;
    }

    public record LastScan(Long id, String status, Instant createdAt, String error) {}

    public record Summary(
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
            long openIssues) {}

    public record CreateRequest(
            String url,
            String branch,
            String name,
            String subPath,
            Integer scanIntervalMinutes,
            String scanCron,
            String requiredAgentLabel,
            UUID sshKeyId) {}

    public record QueuedScan(Long id, String status) {}

    /** The list, with each target's latest scan and how many issues are waiting on it. */
    @GetMapping
    public List<Summary> list() {
        Map<Long, LastScan> latest = latestScans();
        Map<Long, Long> open = openIssueCounts();

        return repositories.findAll().stream()
                .map(repository -> new Summary(
                        repository.getId(),
                        repository.getUrl(),
                        repository.getBranch(),
                        repository.getName(),
                        repository.getSubPath(),
                        displayName(repository),
                        repository.getScanIntervalMinutes(),
                        repository.getScanCron(),
                        repository.getRequiredAgentLabel(),
                        repository.getSshKeyId(),
                        repository.getLastScheduledScanAt(),
                        latest.get(repository.getId()),
                        open.getOrDefault(repository.getId(), 0L)))
                .toList();
    }

    @RequiresAdministrator
    @PostMapping
    public Summary create(
            @RequestBody CreateRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        String url = trim(body.url());
        // Validated **here and not only at scan time**: an unvalidated URL reaching a git clone
        // is arbitrary code execution, not a typo.
        RepositoryUrl.validate(url).ifPresent(message -> {
            throw new IllegalArgumentException(message);
        });

        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch(trim(body.branch()).isEmpty() ? "main" : trim(body.branch()));
        repository.setName(optional(body.name()));
        repository.setSubPath(optional(body.subPath()));
        repository.setScanIntervalMinutes(body.scanIntervalMinutes());
        // Validated at the entry point: discovering that an expression was rejected by watching
        // scans *not* happen is the expensive way.
        repository.setScanCron(validatedCron(body.scanCron()));
        // Normalized on entry: without it, "Production" here and "production" on the agent would
        // never meet, and the scan would wait for an agent that is present.
        repository.setRequiredAgentLabel(AgentLabels.normalizeRequirement(body.requiredAgentLabel()).orElse(null));
        repository.setSshKeyId(body.sshKeyId());

        RepositoryEntity saved = repositories.save(repository);
        record(principal, request, AuditOperation.SETTING_UPDATED, saved.getId(), "Repository added: " + saved.getUrl());
        return list().stream()
                .filter(summary -> summary.id().equals(saved.getId()))
                .findFirst()
                .orElseThrow();
    }

    /**
     * Queues a scan of this repository.
     *
     * <p>Administrators only: a scan costs machine time and network, and the queue is shared.
     */
    @RequiresAdministrator
    @PostMapping("/{id}/scan")
    public QueuedScan triggerScan(
            @PathVariable long id,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        RepositoryEntity repository = repositories.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Repository not found."));

        ScanEntity scan = trigger.trigger(repository);
        record(principal, request, AuditOperation.SCAN_TRIGGERED, scan.getId(),
                "Scan requested: " + repository.getUrl());
        return new QueuedScan(scan.getId(), scan.getStatus());
    }

    @RequiresAdministrator
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(
            @PathVariable long id,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        RepositoryEntity repository = repositories.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Repository not found."));

        // Scans, findings and issues follow by cascade. That is intended: keeping the backlog of
        // a target that no longer exists would have it counting towards the totals for ever with
        // nobody able to act on it.
        repositories.deleteById(id);
        record(principal, request, AuditOperation.SETTING_UPDATED, id, "Repository deleted: " + repository.getUrl());
    }

    private Map<Long, LastScan> latestScans() {
        Map<Long, LastScan> latest = new HashMap<>();
        for (Object[] row : scans.findLatestPerRepository()) {
            latest.put(
                    ((Number) row[0]).longValue(),
                    new LastScan(
                            ((Number) row[1]).longValue(), (String) row[2], (Instant) row[3], (String) row[4]));
        }
        return latest;
    }

    private Map<Long, Long> openIssueCounts() {
        Map<Long, Long> counts = new HashMap<>();
        for (Object[] row : issues.countOpenByRepository(IssueState.OPEN.wireName())) {
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

    /** What the screen calls it: the operator's name, or the URL when they gave none. */
    private static String displayName(RepositoryEntity repository) {
        String name = trim(repository.getName());
        return name.isEmpty() ? repository.getUrl() : name;
    }

    /**
     * A valid cron expression, {@code null}, or a 400 the operator can read.
     *
     * <p>A 400 and not a 500: the expression came from the user, and the message carries the
     * expected format.
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

package com.asmolabs.zanshin.core.api;

import com.fasterxml.jackson.annotation.JsonProperty;
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
import com.asmolabs.zanshin.common.domain.access.Visibility;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.VisibilityService;
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
import org.springframework.web.bind.annotation.PatchMapping;
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
    private final VisibilityService visibility;

    public RepositoriesController(
            GitRepositories repositories,
            Scans scans,
            Issues issues,
            ScanTriggerService trigger,
            AuditLogService audit,
            VisibilityService visibility) {
        this.repositories = repositories;
        this.scans = scans;
        this.issues = issues;
        this.trigger = trigger;
        this.audit = audit;
        this.visibility = visibility;
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

    /** The names the Angular client sends. See {@code ClientContractTest} for why they differ. */
    public record CreateRequest(
            String url,
            String branch,
            String name,
            String subPath,
            Integer scanIntervalMinutes,
            String scanCron,
            @JsonProperty("required_agent_label") String requiredAgentLabel,
            UUID sshKeyId) {}

    public record QueuedScan(Long id, String status) {}

    /** The list, with each target's latest scan and how many issues are waiting on it. */
    @GetMapping
    public List<Summary> list(@AuthenticationPrincipal ZanshinPrincipal principal) {
        Visibility allowed = visibility.of(
                principal.user().orElse(null), principal.credentialRestriction());
        Map<Long, LastScan> latest = latestScans();
        Map<Long, Long> open = openIssueCounts();

        return repositories.findAll().stream()
                .filter(repository -> allowed.permits(new ScanTarget.Repository(repository.getId())))
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
        return list(principal).stream()
                .filter(summary -> summary.id().equals(saved.getId()))
                .findFirst()
                .orElseThrow();
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
    @RequiresAdministrator
    @PatchMapping("/{id}")
    public Summary update(
            @PathVariable long id,
            @RequestBody CreateRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        RepositoryEntity repository = repositories
                .findById(id)
                .orElseThrow(() -> new NoSuchElementException("No repository with id " + id + "."));
        Visibilities.requireVisible(
                new ScanTarget.Repository(id),
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));

        String previousUrl = repository.getUrl();
        if (body.url() != null) {
            String url = trim(body.url());
            // Validated on update exactly as on create: an unvalidated URL reaching a git clone
            // is arbitrary code execution, and a row edited later is no safer than a row added.
            RepositoryUrl.validate(url).ifPresent(message -> {
                throw new IllegalArgumentException(message);
            });
            repository.setUrl(url);
        }
        if (body.branch() != null) {
            repository.setBranch(trim(body.branch()).isEmpty() ? "main" : trim(body.branch()));
        }
        if (body.name() != null) {
            repository.setName(optional(body.name()));
        }
        if (body.subPath() != null) {
            repository.setSubPath(optional(body.subPath()));
        }
        if (body.scanIntervalMinutes() != null) {
            repository.setScanIntervalMinutes(body.scanIntervalMinutes());
        }
        if (body.scanCron() != null) {
            repository.setScanCron(validatedCron(body.scanCron()));
        }
        if (body.requiredAgentLabel() != null) {
            repository.setRequiredAgentLabel(
                    AgentLabels.normalizeRequirement(body.requiredAgentLabel()).orElse(null));
        }
        if (body.sshKeyId() != null) {
            repository.setSshKeyId(body.sshKeyId());
        }

        RepositoryEntity saved = repositories.save(repository);
        String moved = saved.getUrl().equals(previousUrl) ? "" : " (was " + previousUrl + ")";
        record(principal, request, AuditOperation.SETTING_UPDATED, saved.getId(),
                "Repository updated: " + saved.getUrl() + moved);

        return list(principal).stream()
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

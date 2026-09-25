package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.targets.AssetTier;
import com.asmolabs.vectispire.common.domain.targets.RepositorySubPath;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.LatestScanRow;
import com.asmolabs.vectispire.core.repositories.OpenIssueCount;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * The repositories under watch: listing them within an allowance, and changing the inventory.
 *
 * <p><b>No transaction of its own, on purpose.</b> Each write is one {@code save}, which carries
 * the repository's own transaction; the route this was lifted from never opened a wider one, and
 * wrapping the lookup and the save together here would change what a concurrent edit sees. It is
 * also what lets each write be audited here, straight after it: the audit entry opens its own
 * transaction, and inside an outer one it would wait on its parent's lock on SQLite, where the
 * lock is the file.
 */
@Service
public class RepositoryAdministrationService {

    private final GitRepositories repositories;
    private final Scans scans;
    private final Issues issues;
    private final ScanTriggerService trigger;
    private final TargetDeletionService targetDeletion;
    private final AuditLogService audit;

    public RepositoryAdministrationService(
            GitRepositories repositories,
            Scans scans,
            Issues issues,
            ScanTriggerService trigger,
            TargetDeletionService targetDeletion,
            AuditLogService audit) {
        this.repositories = repositories;
        this.scans = scans;
        this.issues = issues;
        this.trigger = trigger;
        this.targetDeletion = targetDeletion;
        this.audit = audit;
    }

    /** A target's most recent scan, whatever its outcome. Shared with the container inventory. */
    public record LatestScan(Long id, String status, Instant createdAt, String error) {}

    /** A repository as the inventory shows it: the row, its latest scan, and what waits on it. */
    public record Listed(RepositoryEntity repository, Optional<LatestScan> latestScan, long openIssues) {}

    /**
     * What an operator asked for, field by field.
     *
     * <p>Strings rather than typed values for the reason the route gives: on update, {@code null}
     * is "leave alone" and the empty string is "clear", and a typed field could not say both.
     */
    public record Changes(
            String url,
            String branch,
            String name,
            String subPath,
            Integer scanIntervalMinutes,
            String scanCron,
            String requiredAgentLabel,
            String sshKeyId,
            String tier) {}

    public record Triggered(RepositoryEntity repository, ScanEntity scan) {}

    /** Every repository the allowance permits, with each one's latest scan and open issue count. */
    public List<Listed> list(Visibility allowed) {
        Map<Long, LatestScan> latest = latestScans();
        Map<Long, Long> open = openIssueCounts();

        return repositories.findAll().stream()
                .filter(repository -> allowed.permits(new ScanTarget.Repository(repository.getId())))
                .map(repository -> new Listed(
                        repository,
                        Optional.ofNullable(latest.get(repository.getId())),
                        open.getOrDefault(repository.getId(), 0L)))
                .toList();
    }

    /**
     * One row of {@link #list}, read the same way.
     *
     * <p>Through the list rather than by id so that what a create or an update answers is
     * exactly the row the inventory will show — latest scan and count included — and so that the
     * allowance decides it the same way.
     */
    public Optional<Listed> listed(Visibility allowed, long id) {
        return list(allowed).stream()
                .filter(listed -> listed.repository().getId().equals(id))
                .findFirst();
    }

    public RepositoryEntity create(Changes changes, RequestActor actor) {
        String url = trim(changes.url());
        // Validated **here and not only at scan time**: an unvalidated URL reaching a git clone
        // is arbitrary code execution, not a typo.
        RepositoryUrl.validate(url).ifPresent(message -> {
            throw new IllegalArgumentException(message);
        });

        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch(trim(changes.branch()).isEmpty() ? "main" : trim(changes.branch()));
        repository.setName(optional(changes.name()));
        // Checked like the URL, and for the same reason: it is resolved against a clone on the
        // scanning host — see RepositorySubPath.
        repository.setSubPath(optional(RepositorySubPath.normalize(changes.subPath())));
        repository.setScanIntervalMinutes(changes.scanIntervalMinutes());
        // Validated at the entry point: discovering that an expression was rejected by watching
        // scans *not* happen is the expensive way.
        repository.setScanCron(validatedCron(changes.scanCron()));
        // Normalized on entry: without it, "Production" here and "production" on the agent would
        // never meet, and the scan would wait for an agent that is present.
        repository.setRequiredAgentLabel(AgentLabels.normalizeRequirement(changes.requiredAgentLabel()).orElse(null));
        repository.setSshKeyId(sshKeyId(changes.sshKeyId()));
        repository.setTier(changes.tier() != null ? AssetTier.fromString(changes.tier()).name() : "TIER_2_BUSINESS_OPERATIONAL");

        RepositoryEntity saved = repositories.save(repository);
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED, String.valueOf(saved.getId()), "Repository added: " + RepositoryUrl.redact(saved.getUrl())));
        return saved;
    }

    /**
     * Applies what was sent and leaves the rest.
     *
     * <p><b>Absent means unchanged, not cleared</b> — see the route for why that convention and
     * not its opposite.
     *
     * <p>The absent row is refused before the allowance is consulted, each in its own words,
     * because that is the order and the wording this route has always answered with.
     *
     * <p>The audit entry names the previous URL as well, redacted, for the reason the route gives.
     */
    public RepositoryEntity update(long id, Changes changes, Visibility allowed, RequestActor actor) {
        RepositoryEntity repository = repositories
                .findById(id)
                .orElseThrow(() -> new NoSuchElementException("No repository with id " + id + "."));
        // Refused as every other route refuses a target it will not name, in the same words.
        RowVisibility.requireVisible(new ScanTarget.Repository(id), allowed);

        String previousUrl = repository.getUrl();
        // The list sends the URL masked; a form saved without touching it sends the mask back,
        // which must leave the stored URL — credential included — as it was.
        if (changes.url() != null && !RepositoryUrl.isMaskedFormOf(trim(changes.url()), previousUrl)) {
            String url = trim(changes.url());
            // Validated on update exactly as on create: an unvalidated URL reaching a git clone
            // is arbitrary code execution, and a row edited later is no safer than a row added.
            RepositoryUrl.validate(url).ifPresent(message -> {
                throw new IllegalArgumentException(message);
            });
            repository.setUrl(url);
        }
        if (changes.branch() != null) {
            repository.setBranch(trim(changes.branch()).isEmpty() ? "main" : trim(changes.branch()));
        }
        if (changes.name() != null) {
            repository.setName(optional(changes.name()));
        }
        if (changes.subPath() != null) {
            repository.setSubPath(optional(RepositorySubPath.normalize(changes.subPath())));
        }
        if (changes.scanIntervalMinutes() != null) {
            repository.setScanIntervalMinutes(changes.scanIntervalMinutes());
        }
        if (changes.scanCron() != null) {
            repository.setScanCron(validatedCron(changes.scanCron()));
        }
        if (changes.requiredAgentLabel() != null) {
            repository.setRequiredAgentLabel(
                    AgentLabels.normalizeRequirement(changes.requiredAgentLabel()).orElse(null));
        }
        if (changes.sshKeyId() != null) {
            repository.setSshKeyId(sshKeyId(changes.sshKeyId()));
        }
        if (changes.tier() != null) {
            repository.setTier(AssetTier.fromString(changes.tier()).name());
        }

        RepositoryEntity saved = repositories.save(repository);
        String moved = saved.getUrl().equals(previousUrl) ? "" : " (was " + RepositoryUrl.redact(previousUrl) + ")";
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED,
                String.valueOf(saved.getId()),
                "Repository updated: " + RepositoryUrl.redact(saved.getUrl()) + moved));
        return saved;
    }

    public Triggered trigger(long id, RequestActor actor) {
        RepositoryEntity repository = repositories.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Repository not found."));
        ScanEntity scan = trigger.trigger(repository);
        audit.record(actor.entry(
                AuditOperation.SCAN_TRIGGERED, String.valueOf(scan.getId()), "Scan requested: " + RepositoryUrl.redact(repository.getUrl())));
        return new Triggered(repository, scan);
    }

    /** Deletes the repository and everything hanging off it. */
    public void delete(long id, RequestActor actor) {
        RepositoryEntity repository = repositories.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Repository not found."));
        targetDeletion.deleteRepository(id);
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED, String.valueOf(id), "Repository deleted: " + RepositoryUrl.redact(repository.getUrl())));
    }

    private Map<Long, LatestScan> latestScans() {
        Map<Long, LatestScan> latest = new HashMap<>();
        for (LatestScanRow row : scans.findLatestPerRepository()) {
            latest.put(row.targetId(), new LatestScan(row.scanId(), row.status(), row.createdAt(), row.error()));
        }
        return latest;
    }

    private Map<Long, Long> openIssueCounts() {
        Map<Long, Long> counts = new HashMap<>();
        for (OpenIssueCount row : issues.countOpenByRepository(IssueState.OPEN.wireName())) {
            counts.put(row.targetId(), row.count());
        }
        return counts;
    }

    /**
     * A valid cron expression, {@code null}, or a 400 the operator can read.
     *
     * <p>A 400 and not a 500: the expression came from the user, and the message carries the
     * expected format.
     */
    static String validatedCron(String expression) {
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

    static String trim(String value) {
        return value == null ? "" : value.trim();
    }

    static String optional(String value) {
        String trimmed = trim(value);
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * Reads the deployment key the form named, where blank means "no key".
     *
     * <p>Rejecting a malformed identifier here rather than storing it matters: a repository
     * pointing at a key that does not exist falls back to the host's own SSH and fails at clone
     * time with "requires authentication" — an error that names neither the wrong identifier nor
     * this form. The 400 arrives while the operator is still looking at the field.
     */
    private static UUID sshKeyId(String value) {
        String trimmed = trim(value);
        if (trimmed.isEmpty()) {
            return null;
        }
        try {
            return UUID.fromString(trimmed);
        } catch (IllegalArgumentException malformed) {
            throw new IllegalArgumentException("\"" + trimmed + "\" is not a valid SSH key identifier.");
        }
    }
}

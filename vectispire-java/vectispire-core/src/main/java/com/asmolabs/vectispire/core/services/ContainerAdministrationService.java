package com.asmolabs.vectispire.core.services;

import static com.asmolabs.vectispire.core.services.RepositoryAdministrationService.optional;
import static com.asmolabs.vectispire.core.services.RepositoryAdministrationService.trim;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.targets.AssetTier;
import com.asmolabs.vectispire.common.domain.targets.ImageReference;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.LatestScanRow;
import com.asmolabs.vectispire.core.repositories.OpenIssueCount;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.RepositoryAdministrationService.LatestScan;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * The container images under watch: listing them within an allowance, and changing the inventory.
 *
 * <p>No transaction of its own, for the same reason as {@link RepositoryAdministrationService}:
 * every write is a single {@code save} carrying the repository's transaction, which is all the
 * routes ever had. It is also what lets each write be audited here, straight after it: the audit
 * entry opens its own transaction, and inside an outer one it would wait on its parent's lock on
 * SQLite, where the lock is the file.
 */
@Service
public class ContainerAdministrationService {

    private final Containers containers;
    private final Scans scans;
    private final Issues issues;
    private final ScanTriggerService trigger;
    private final TargetDeletionService targetDeletion;
    private final AuditLogService audit;

    public ContainerAdministrationService(
            Containers containers,
            Scans scans,
            Issues issues,
            ScanTriggerService trigger,
            TargetDeletionService targetDeletion,
            AuditLogService audit) {
        this.containers = containers;
        this.scans = scans;
        this.issues = issues;
        this.trigger = trigger;
        this.targetDeletion = targetDeletion;
        this.audit = audit;
    }

    /** An image as the inventory shows it: the row, its latest scan, and what waits on it. */
    public record Listed(ContainerEntity container, Optional<LatestScan> latestScan, long openIssues) {}

    /** What an operator asked for; {@code null} is "leave alone" on update, as for repositories. */
    public record Changes(
            String registry,
            String imageName,
            String tag,
            Integer scanIntervalMinutes,
            String scanCron,
            String requiredAgentLabel,
            String tier) {}

    public record Triggered(ContainerEntity container, ScanEntity scan) {}

    public List<Listed> list(Visibility allowed) {
        Map<Long, LatestScan> latest = latestScans();
        Map<Long, Long> open = openIssueCounts();

        return containers.findAll().stream()
                .filter(container -> allowed.permits(new ScanTarget.Container(container.getId())))
                .map(container -> new Listed(
                        container,
                        Optional.ofNullable(latest.get(container.getId())),
                        open.getOrDefault(container.getId(), 0L)))
                .toList();
    }

    /** One row of {@link #list}, read through it for the reason given on the repository side. */
    public Optional<Listed> listed(Visibility allowed, long id) {
        return list(allowed).stream()
                .filter(listed -> listed.container().getId().equals(id))
                .findFirst();
    }

    public ContainerEntity create(Changes changes, RequestActor actor) {
        ImageReference reference = new ImageReference(
                optional(changes.registry()),
                trim(changes.imageName()),
                trim(changes.tag()).isEmpty() ? "latest" : trim(changes.tag()));
        // Validated at the entry point, like a repository URL: a reference reaching a `docker
        // pull` unchecked is not a typo, it is whatever the operator's daemon will fetch.
        reference.validate().ifPresent(message -> {
            throw new IllegalArgumentException(message);
        });

        ContainerEntity container = new ContainerEntity();
        container.setRegistry(reference.registry());
        container.setImageName(reference.imageName());
        container.setTag(reference.tag());
        container.setScanIntervalMinutes(changes.scanIntervalMinutes());
        container.setScanCron(validatedCron(changes.scanCron()));
        container.setRequiredAgentLabel(AgentLabels.normalizeRequirement(changes.requiredAgentLabel()).orElse(null));
        container.setTier(changes.tier() != null ? AssetTier.fromString(changes.tier()).name() : "TIER_2_BUSINESS_OPERATIONAL");

        ContainerEntity saved = containers.save(container);
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED, String.valueOf(saved.getId()), "Image added: " + referenceOf(saved).format()));
        return saved;
    }

    /**
     * Applies what was sent and leaves the rest — see the route for the conventions, and for why
     * the interval is cleared by zero rather than by emptiness.
     *
     * <p>The absent row is refused before the allowance is consulted, each in its own words: the
     * order and the wording this route has always answered with.
     *
     * <p>The audit entry names the previous reference as well, for the reason the route gives.
     */
    public ContainerEntity update(long id, Changes changes, Visibility allowed, RequestActor actor) {
        ContainerEntity container = containers
                .findById(id)
                .orElseThrow(() -> new NoSuchElementException("No image with id " + id + "."));
        // The wording `Visibilities.requireVisible` gives a hidden target.
        if (!allowed.permits(new ScanTarget.Container(id))) {
            throw new NoSuchElementException("Target not found.");
        }

        String previousReference = referenceOf(container).format();

        // Validated as a whole and not field by field: a registry, a name and a tag are only
        // legal together, and a reference reaching a `docker pull` unchecked is whatever the
        // operator's daemon will fetch — as true of a row edited later as of a row added.
        ImageReference reference = new ImageReference(
                changes.registry() != null ? optional(changes.registry()) : container.getRegistry(),
                changes.imageName() != null ? trim(changes.imageName()) : container.getImageName(),
                changes.tag() != null ? (trim(changes.tag()).isEmpty() ? "latest" : trim(changes.tag())) : container.getTag());
        reference.validate().ifPresent(message -> {
            throw new IllegalArgumentException(message);
        });
        container.setRegistry(reference.registry());
        container.setImageName(reference.imageName());
        container.setTag(reference.tag());

        if (changes.scanIntervalMinutes() != null) {
            container.setScanIntervalMinutes(changes.scanIntervalMinutes());
        }
        if (changes.scanCron() != null) {
            container.setScanCron(validatedCron(changes.scanCron()));
        }
        if (changes.requiredAgentLabel() != null) {
            // Normalized on update as on create: "Production" here and "production" on the agent
            // would never meet, and the scan would wait for an agent that is present.
            container.setRequiredAgentLabel(
                    AgentLabels.normalizeRequirement(changes.requiredAgentLabel()).orElse(null));
        }
        if (changes.tier() != null) {
            container.setTier(AssetTier.fromString(changes.tier()).name());
        }

        ContainerEntity saved = containers.save(container);
        String now = referenceOf(saved).format();
        String moved = now.equals(previousReference) ? "" : " (was " + previousReference + ")";
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED, String.valueOf(saved.getId()), "Image updated: " + now + moved));
        return saved;
    }

    public Triggered trigger(long id, RequestActor actor) {
        ContainerEntity container = containers.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Image not found."));
        ScanEntity scan = trigger.trigger(container);
        audit.record(actor.entry(
                AuditOperation.SCAN_TRIGGERED, String.valueOf(scan.getId()), "Scan requested: " + referenceOf(container).format()));
        return new Triggered(container, scan);
    }

    /** Deletes the image and everything hanging off it. */
    public void delete(long id, RequestActor actor) {
        ContainerEntity container = containers.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Image not found."));
        targetDeletion.deleteContainer(id);
        audit.record(actor.entry(
                AuditOperation.SETTING_UPDATED, String.valueOf(id), "Image deleted: " + referenceOf(container).format()));
    }

    public static ImageReference referenceOf(ContainerEntity container) {
        return new ImageReference(container.getRegistry(), container.getImageName(), container.getTag());
    }

    private Map<Long, LatestScan> latestScans() {
        Map<Long, LatestScan> latest = new HashMap<>();
        for (LatestScanRow row : scans.findLatestPerContainer()) {
            latest.put(row.targetId(), new LatestScan(row.scanId(), row.status(), row.createdAt(), row.error()));
        }
        return latest;
    }

    private Map<Long, Long> openIssueCounts() {
        Map<Long, Long> counts = new HashMap<>();
        for (OpenIssueCount row : issues.countOpenByContainer(IssueState.OPEN.wireName())) {
            counts.put(row.targetId(), row.count());
        }
        return counts;
    }

    /**
     * The repository route's validation, called rather than copied: the two dialogs put the
     * server's message straight on screen, and an operator who learned the expected format on one
     * screen should not have to learn it again on the other. Two copies of the sentence had to be
     * kept identical by hand before this.
     */
    private static String validatedCron(String expression) {
        return RepositoryAdministrationService.validatedCron(expression);
    }
}

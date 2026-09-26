package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Components;
import com.asmolabs.vectispire.core.services.shared.TargetNaming;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;

/**
 * "Do we ship this library, and in which release?" — the component inventory, narrowed to the
 * targets the caller may see. Why the inventory answers what the backlog cannot is on {@code
 * InventoryController}.
 */
@Service
public class InventoryQueryService {

    /**
     * A component in a monorepo can appear in thousands of scans. The cap is on the answer, not
     * on the search: a narrower query is the right response to a truncated one, and saying so is
     * what stops a reader concluding "that is all of them".
     */
    private static final int MAX_ROWS = 500;

    private final Components components;
    private final TargetNaming naming;

    public InventoryQueryService(Components components, TargetNaming naming) {
        this.components = components;
        this.naming = naming;
    }

    /**
     * @param projectVersion the version of the <b>project</b>, from its manifest — null for a
     *     scan that ran before Vectispire read manifests, and for a tree that carries none
     * @param componentVersion the version of the <b>library</b>. The two sit side by side because
     *     confusing them is the one mistake that makes the answer useless
     */
    public record Occurrence(
            String component,
            String componentVersion,
            String purl,
            String type,
            Boolean direct,
            String targetKind,
            Long targetId,
            String targetName,
            String branch,
            String projectVersion,
            Long scanId,
            Instant scannedAt) {}

    /** @param truncated said plainly: a capped list read as complete is a wrong answer */
    public record Results(List<Occurrence> occurrences, int total, boolean truncated) {}

    /** @throws IllegalArgumentException for a blank name: searching for everything is not a search */
    public Results search(String name, String version, Visibility allowed) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("A component name is required.");
        }

        TargetNaming.Names names = naming.all();

        // One over the cap, so "there are more" is known rather than guessed from a full page.
        List<Object[]> rows = components.search(
                "%" + name.trim().toLowerCase(Locale.ROOT) + "%",
                version == null || version.isBlank() ? null : version.trim(),
                Limit.of(MAX_ROWS + 1));

        List<Occurrence> occurrences = rows.stream()
                .map(row -> occurrenceOf((ComponentEntity) row[0], (ScanEntity) row[1], names))
                // Filtered after the query for the same reason the scan history is: the
                // restriction is a set of targets, and expressing it in SQL would duplicate a
                // predicate that already exists — and getting it wrong here leaks an inventory.
                .filter(occurrence -> allowed.permits(targetOf(occurrence)))
                .toList();

        boolean truncated = occurrences.size() > MAX_ROWS;
        return new Results(
                truncated ? occurrences.subList(0, MAX_ROWS) : occurrences,
                Math.min(occurrences.size(), MAX_ROWS),
                truncated);
    }

    /**
     * The versions of one component the caller may see. Empty for a blank name — the screen's
     * second field asks before anything is typed, and that is not a malformed request.
     */
    public List<String> versions(String name, Visibility allowed) {
        if (name == null || name.isBlank()) {
            return List.of();
        }

        // The cap is applied to rows, and a row is a (version, target) pair, so a version present
        // on many targets costs many rows. Deliberately generous for that reason: capping tightly
        // here would drop versions the caller may see, which reads as "we do not run it".
        return components.versionsOf("%" + name.trim().toLowerCase(Locale.ROOT) + "%", Limit.of(MAX_ROWS))
                .stream()
                .filter(row -> allowed.permits(targetOf(row)))
                .map(row -> (String) row[0])
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    /** The target a {@code (version, repoId, containerId)} row was catalogued on. */
    private static ScanTarget targetOf(Object[] row) {
        Long repoId = (Long) row[1];
        Long containerId = (Long) row[2];
        if (repoId != null) {
            return new ScanTarget.Repository(repoId);
        }
        return containerId == null ? null : new ScanTarget.Container(containerId);
    }

    private static ScanTarget targetOf(Occurrence occurrence) {
        if (occurrence.targetId() == null) {
            return null;
        }
        return "repository".equals(occurrence.targetKind())
                ? new ScanTarget.Repository(occurrence.targetId())
                : new ScanTarget.Container(occurrence.targetId());
    }

    private static Occurrence occurrenceOf(ComponentEntity component, ScanEntity scan, TargetNaming.Names names) {
        boolean isRepository = scan.getRepoId() != null;
        Long targetId = isRepository ? scan.getRepoId() : scan.getContainerId();

        return new Occurrence(
                component.getName(),
                component.getVersion(),
                component.getPurl(),
                component.getType(),
                component.getIsDirect(),
                isRepository ? "repository" : "container",
                targetId,
                names.of(scan.getRepoId(), scan.getContainerId()),
                scan.getBranch(),
                scan.getVersion(),
                scan.getId(),
                scan.getCreatedAt());
    }
}

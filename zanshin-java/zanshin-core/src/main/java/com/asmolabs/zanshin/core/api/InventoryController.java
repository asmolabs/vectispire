package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.access.Visibility;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.ComponentEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Components;
import com.asmolabs.zanshin.core.services.TargetNaming;
import com.asmolabs.zanshin.core.services.VisibilityService;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import org.springframework.data.domain.Limit;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * "Do we ship this library, and in which release?"
 *
 * <p><b>The question the backlog cannot answer.</b> An issue exists only where something is
 * wrong, so searching issues finds the projects with a <em>vulnerable</em> log4j — and the day a
 * vulnerability is published, no scanner knows about it yet and every backlog is silent on
 * exactly the component being asked about. The inventory is the component list itself, flagged
 * or not.
 *
 * <p><b>The project's own version is the point of the answer, not decoration.</b> "Yes, we use
 * it" leaves the work undone; "it went out in 1.17.6 and is gone from 1.18.0" is what lets
 * somebody name the affected deliveries. That is why every row carries the version the scan read
 * from the project's manifest, beside the version of the component itself.
 */
@RestController
@RequestMapping("/api/v1/inventory")
@RequiresAccount
public class InventoryController {

    /**
     * A component in a monorepo can appear in thousands of scans. The cap is on the answer, not
     * on the search: a narrower query is the right response to a truncated one, and saying so is
     * what stops a reader concluding "that is all of them".
     */
    private static final int MAX_ROWS = 500;

    private final Components components;
    private final TargetNaming naming;
    private final VisibilityService visibility;

    public InventoryController(Components components, TargetNaming naming, VisibilityService visibility) {
        this.components = components;
        this.naming = naming;
        this.visibility = visibility;
    }

    /**
     * @param projectVersion the version of the <b>project</b>, from its manifest — null for a
     *     scan that ran before Zanshin read manifests, and for a tree that carries none
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

    @GetMapping("/search")
    public Results search(
            @AuthenticationPrincipal ZanshinPrincipal principal,
            @RequestParam String name,
            @RequestParam(required = false) String version) {

        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("A component name is required.");
        }

        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
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

    /** The versions of one component that were ever catalogued, for the screen's second field. */
    @GetMapping("/versions")
    public List<String> versions(@RequestParam String name) {
        if (name == null || name.isBlank()) {
            return List.of();
        }
        return components.versionsOf("%" + name.trim().toLowerCase(Locale.ROOT) + "%", Limit.of(200)).stream()
                .filter(java.util.Objects::nonNull)
                .toList();
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

package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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

    private final ComponentRepository components;
    private final TargetNaming naming;
    private final ScanCatalog scans;

    public InventoryQueryService(ComponentRepository components, TargetNaming naming, ScanCatalog scans) {
        this.components = components;
        this.naming = naming;
        this.scans = scans;
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

    /**
     * Every distinct package URL the inventory holds — what rule coverage compares the rule sets with.
     *
     * <p>This method and the three below exist because the components table is this module's: rule
     * coverage and the compliance summary read it through the repository while the code was
     * packaged by layer, a dependency on inventory neither showed. Each delegates to the query it
     * replaces, with no transaction of its own, as before.
     */
    public List<String> distinctPurls() {
        return components.distinctPurls();
    }

    /** Every distinct package URL with the target its scan was of, as {@code ComponentRepository} returns them. */
    public List<Object[]> distinctPurlsByTarget() {
        return components.distinctPurlsByTarget();
    }

    /** The repositories whose scans produced an inventory. */
    public List<Long> distinctRepositoriesWithComponents() {
        return components.distinctRepositoriesWithComponents();
    }

    /** The container images whose scans produced an inventory. */
    public List<Long> distinctContainersWithComponents() {
        return components.distinctContainersWithComponents();
    }

    /** @throws InvalidInputException for a blank name: searching for everything is not a search */
    public Results search(String name, String version, Visibility allowed) {
        if (name == null || name.isBlank()) {
            throw new InvalidInputException("A component name is required.");
        }

        TargetNaming.Names names = naming.all();

        // One over the cap, so "there are more" is known rather than guessed from a full page.
        List<ComponentEntity> rows = components.search(
                "%" + name.trim().toLowerCase(Locale.ROOT) + "%",
                version == null || version.isBlank() ? null : version.trim(),
                Limit.of(MAX_ROWS + 1));

        // Filtered after the query for the same reason the scan history is: the restriction is a set
        // of targets, and expressing it in SQL would duplicate a predicate that already exists — and
        // getting it wrong here leaks an inventory.
        List<ComponentEntity> visible = rows.stream()
                .filter(row -> allowed.permits(targetOf(row.getRepoId(), row.getContainerId())))
                .toList();

        // The branch and the project version are the scan's, asked for the page's scans only: at most
        // the cap and one, so well under a statement's bind limit, and batched by the catalogue anyway.
        // A scan gone between the two statements takes its rows with it, as the join did.
        Map<Long, ScanCatalog.ScanLabel> labels = scans.labelsOf(
                visible.stream().map(ComponentEntity::getScanId).distinct().toList());
        List<Occurrence> occurrences = visible.stream()
                .filter(row -> labels.containsKey(row.getScanId()))
                .map(row -> occurrenceOf(row, labels.get(row.getScanId()), names))
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
                .filter(row -> allowed.permits(targetOf((Long) row[1], (Long) row[2])))
                .map(row -> (String) row[0])
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    /** The target a row was catalogued on: its repository if it has one, else its image. */
    private static ScanTarget targetOf(Long repoId, Long containerId) {
        if (repoId != null) {
            return new ScanTarget.Repository(repoId);
        }
        return containerId == null ? null : new ScanTarget.Container(containerId);
    }

    /** @param label the scan's branch and project version, which the row does not carry */
    private static Occurrence occurrenceOf(
            ComponentEntity component, ScanCatalog.ScanLabel label, TargetNaming.Names names) {
        Long repoId = component.getRepoId();
        Long containerId = component.getContainerId();
        boolean isRepository = repoId != null;
        Long targetId = isRepository ? repoId : containerId;

        return new Occurrence(
                component.getName(),
                component.getVersion(),
                component.getPurl(),
                component.getType(),
                component.getIsDirect(),
                isRepository ? "repository" : "container",
                targetId,
                names.of(repoId, containerId),
                label.branch(),
                label.version(),
                component.getScanId(),
                component.getScanCreatedAt());
    }
}

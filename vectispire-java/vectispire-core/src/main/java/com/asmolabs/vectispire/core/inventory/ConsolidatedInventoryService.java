package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.sbom.ComponentOrigin;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.queries.NewestCompletedScanRow;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import com.fasterxml.jackson.annotation.JsonValue;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * A project's consolidated SBOM: the components of the newest completed scan of each of its visible
 * repositories and images, merged, each saying which targets carry it (decision 0023, "consolidated
 * SBOM per project").
 *
 * <p><b>The newest completed scan of each target, and nothing older.</b> An older scan's inventory in
 * place of a newest one without an SBOM would present last month's tree as today's; the target is said
 * to be unknown instead ({@link InventoryState#ABSENT}, {@link InventoryState#NEVER_SCANNED}) and the
 * document says it is not complete. A merge that silently skipped a target whose SBOM step failed would
 * read "we do not ship log4j" of a product nobody looked at (decision 0007).
 *
 * <p><b>Merged by package URL and version</b> — by name and version for a component the SBOM gave no
 * package URL — so a library carried by three of a product's repositories is one line naming the
 * three, and two versions of it are two lines: the version is what an advisory is about.
 *
 * <p><b>The caller has already been refused or admitted</b>: this module's services do not use {@code
 * access} ({@code ArchitectureTest.accessForRoutesOnly}), so the route resolves the scope through {@code
 * targets}' guard and hands over the proof, {@link VisibleScope}. Only its targets are read — never the
 * estate's scans, filtered afterwards.
 */
@Service
@Transactional(readOnly = true)
public class ConsolidatedInventoryService {

    private final ScanCatalog scans;
    private final ComponentCatalog components;
    private final TargetNaming naming;

    public ConsolidatedInventoryService(ScanCatalog scans, ComponentCatalog components, TargetNaming naming) {
        this.scans = scans;
        this.components = components;
        this.naming = naming;
    }

    /** What is known of a target's inventory, read off its newest completed scan. */
    public enum InventoryState {
        /** Its newest completed scan's components are in the inventory, and merged. */
        LISTED("listed"),
        /**
         * Its newest completed scan holds an SBOM and the inventory holds no component of it: an SBOM
         * that listed nothing. A scan from before the inventory existed reads so too until the backfill
         * indexes it, which it does within a few maintenance ticks.
         */
        EMPTY("empty"),
        /**
         * Its newest completed scan holds no SBOM and none of its components was indexed — the SBOM step
         * failed, or the payload was purged before it was read. Unknown, never "nothing".
         */
        ABSENT("absent"),
        /** No completed scan: nobody has looked. */
        NEVER_SCANNED("never_scanned");

        private final String wireName;

        InventoryState(String wireName) {
            this.wireName = wireName;
        }

        @JsonValue
        public String wireName() {
            return wireName;
        }

        /** Whether the merge speaks for this target: listed, or listed as nothing. */
        public boolean known() {
            return this == LISTED || this == EMPTY;
        }
    }

    /** A target, as a merged component names the ones that carry it. */
    public record ComponentTarget(String kind, long id, String name) {}

    /**
     * One visible target of the scope and what the merge read of it.
     *
     * @param scanId its newest completed scan, null when it has none
     * @param scannedAt when that scan was queued
     * @param componentCount the components that scan listed, before the merge
     */
    public record TargetInventory(
            String kind, long id, String name, Long scanId, Instant scannedAt, InventoryState inventory, int componentCount) {}

    /**
     * A component carried by one or more of the scope's visible targets.
     *
     * @param purl null where the SBOM gave none; the component is then merged by name and version
     * @param targets the visible targets whose newest completed scan lists it, repositories then images
     * @param sources who listed it across those targets, {@code build} and {@code scanner} in that order:
     *     the build's SBOM, the scanner, or both (decision 0039)
     */
    public record MergedComponent(
            String name, String version, String purl, String type, List<ComponentTarget> targets, List<String> sources) {}

    /**
     * @param kind {@code project} (a solution's is not offered yet)
     * @param partial the project holds targets the caller does not see; the merge covers the visible ones
     * @param complete every visible target's inventory is known ({@code listed} or {@code empty}); false
     *     when one is {@code absent} or {@code never_scanned}, and the components then do not speak for it
     * @param targets every visible target, with what was read of it
     * @param components the merge, sorted by name, then version
     */
    public record ConsolidatedInventory(
            String kind,
            long id,
            String name,
            boolean partial,
            boolean complete,
            List<TargetInventory> targets,
            List<MergedComponent> components) {}

    public ConsolidatedInventory of(VisibleScope scope) {
        List<ScanTarget> targets = scope.targets();
        Map<ScanTarget, NewestCompletedScanRow> newest = scans.newestCompleted(targets);
        Map<Long, List<ComponentCatalog.Component>> byScan =
                components.componentsOf(newest.values().stream().map(NewestCompletedScanRow::scanId).toList());
        TargetNaming.Names names = naming.forIds(
                targets.stream().filter(ScanTarget.Repository.class::isInstance)
                        .map(target -> ((ScanTarget.Repository) target).id()).toList(),
                targets.stream().filter(ScanTarget.Container.class::isInstance)
                        .map(target -> ((ScanTarget.Container) target).id()).toList());

        List<TargetInventory> read = new ArrayList<>();
        Map<Key, Merging> merged = new LinkedHashMap<>();
        for (ScanTarget target : targets) {
            ComponentTarget ref = refOf(target, names);
            NewestCompletedScanRow scan = newest.get(target);
            if (scan == null) {
                read.add(new TargetInventory(ref.kind(), ref.id(), ref.name(), null, null, InventoryState.NEVER_SCANNED, 0));
                continue;
            }
            List<ComponentCatalog.Component> listed = byScan.getOrDefault(scan.scanId(), List.of());
            InventoryState state = !listed.isEmpty()
                    ? InventoryState.LISTED
                    : (scan.sbomStored() ? InventoryState.EMPTY : InventoryState.ABSENT);
            read.add(new TargetInventory(
                    ref.kind(), ref.id(), ref.name(), scan.scanId(), scan.createdAt(), state, listed.size()));
            for (ComponentCatalog.Component component : listed) {
                merged.computeIfAbsent(Key.of(component), key -> new Merging(component)).carriedBy(ref, component.origin());
            }
        }

        List<MergedComponent> merge = merged.values().stream()
                .map(Merging::done)
                .sorted(Comparator.comparing(MergedComponent::name, String.CASE_INSENSITIVE_ORDER)
                        .thenComparing(MergedComponent::version, Comparator.nullsFirst(Comparator.naturalOrder()))
                        .thenComparing(MergedComponent::purl, Comparator.nullsFirst(Comparator.naturalOrder())))
                .toList();
        return new ConsolidatedInventory(
                scope.kind().wireName(),
                scope.id(),
                scope.name(),
                scope.partial(),
                read.stream().allMatch(target -> target.inventory().known()),
                List.copyOf(read),
                merge);
    }

    private static ComponentTarget refOf(ScanTarget target, TargetNaming.Names names) {
        return switch (target) {
            case ScanTarget.Repository repository ->
                    new ComponentTarget("repository", repository.id(), names.of(repository.id(), null));
            case ScanTarget.Container container ->
                    new ComponentTarget("container", container.id(), names.of(null, container.id()));
        };
    }

    /**
     * What makes two listed components one: the package URL, or the name where there is none, and the
     * version. A purl usually carries the version already; it is compared all the same, so that two
     * SBOMs writing one purl for two versions stay two lines.
     */
    private record Key(String identity, String version) {

        static Key of(ComponentCatalog.Component component) {
            String identity = component.purl() != null && !component.purl().isBlank()
                    ? "purl:" + component.purl()
                    : "name:" + component.name();
            return new Key(identity, component.version());
        }
    }

    /** A merged line being built: the first listing names it, every listing adds its target once. */
    private static final class Merging {

        private final ComponentCatalog.Component first;
        private final List<ComponentTarget> targets = new ArrayList<>();
        private boolean fromBuild;
        private boolean fromScanner;

        Merging(ComponentCatalog.Component first) {
            this.first = first;
        }

        void carriedBy(ComponentTarget target, ComponentOrigin origin) {
            if (targets.stream().noneMatch(known -> Objects.equals(known, target))) {
                targets.add(target);
            }
            if (origin.fromBuild()) {
                fromBuild = true;
            }
            if (origin != ComponentOrigin.BUILD) {
                fromScanner = true;
            }
        }

        MergedComponent done() {
            String purl = first.purl() != null && !first.purl().isBlank() ? first.purl() : null;
            List<String> sources = new ArrayList<>();
            if (fromBuild) {
                sources.add("build");
            }
            if (fromScanner) {
                sources.add("scanner");
            }
            return new MergedComponent(first.name(), first.version(), purl, first.type(), List.copyOf(targets),
                    List.copyOf(sources));
        }
    }
}

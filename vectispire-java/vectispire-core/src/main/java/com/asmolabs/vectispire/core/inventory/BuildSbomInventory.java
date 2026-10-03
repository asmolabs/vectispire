package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.sbom.BuildSbom;
import com.asmolabs.vectispire.common.domain.sbom.ComponentOrigin;
import com.asmolabs.vectispire.common.domain.sbom.InventoryCompletion;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomComponentRepository;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomEntity;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomRepository;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanOrigin;
import com.asmolabs.vectispire.core.scanning.persistence.queries.NewestCompletedScanRow;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * A build's SBOM, kept for its repository, and the scans' inventories it completes (G10, decision 0039).
 *
 * <h2>Which SBOM completes which scan</h2>
 *
 * <p><b>A scan's inventory is what its scanner listed, completed by the newest build SBOM of its
 * repository</b> that states the scan's branch or no branch — whenever that SBOM arrived. The rule of the
 * completion itself — union, the build's stated version winning, matched by purl — is {@link
 * InventoryCompletion}'s. Two moments apply it:
 *
 * <ul>
 *   <li><b>A scan's inventory is written</b> ({@link #complete(ScanOrigin)}): a nightly scan of an
 *       unchanged tree keeps the versions and the transitive libraries the last build stated. Requiring
 *       the SBOM to be newer than the scan was tried on paper and refused: every scheduled scan after a
 *       quiet week would have brought the false "no" back until somebody pushed.
 *   <li><b>An SBOM arrives</b> ({@link #record}): the repository's newest completed scan holding an SBOM is
 *       completed again, in the import's transaction, so the inventory, the licences and the checklist
 *       lines read it as soon as the import is answered.
 * </ul>
 *
 * <p><b>Older scans keep what they were given.</b> A scan's inventory is history: scan 12, completed by
 * import 3, still says so after import 4 completed scan 13. Only the newest scan moves on an import.
 *
 * <p><b>A scan that kept no inventory is not completed</b> — one whose SBOM step failed, or whose SBOM
 * the payload retention purged before it was indexed. The build's word completes a scanner's inventory;
 * it does not stand in for a scan that did not look (decision 0007), and the inventory keeps saying
 * "absent" where it did. A scan whose payload was purged <em>after</em> its inventory was written still
 * holds the scanner's rows, which the component rules read, and is completed like any other.
 *
 * <p>Nothing here opens or resolves an issue, and nothing is matched against advisories: the
 * vulnerability matcher runs inside the scan, on the scanner's SBOM.
 */
@Service
public class BuildSbomInventory {

    /** How many imports a repository's history answers. */
    static final int HISTORY = 50;

    private final BuildSbomRepository imports;
    private final BuildSbomComponentRepository listed;
    private final ComponentRepository components;
    private final ScanCatalog scans;

    public BuildSbomInventory(BuildSbomRepository imports, BuildSbomComponentRepository listed,
            ComponentRepository components, ScanCatalog scans) {
        this.imports = imports;
        this.listed = listed;
        this.components = components;
        this.scans = scans;
    }

    /**
     * What the import's governance established — the source and key it came through, and the pipeline's
     * word, already bounded by the caller.
     */
    public record Accepted(long sourceId, String sourceSlug, long repoId, String commit, String branch,
            String documentSha256, Instant importedAt, String importedBy, UUID apiKeyId) {}

    /**
     * Keeps an SBOM and completes its repository's newest scan with the newest SBOM — in the caller's
     * transaction, which also queues what reacts to the import: both commit together or not at all.
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public BuildSbomView record(Accepted accepted, BuildSbom sbom) {
        BuildSbomEntity row = new BuildSbomEntity();
        row.setSourceId(accepted.sourceId());
        row.setSourceSlug(accepted.sourceSlug());
        row.setRepoId(accepted.repoId());
        row.setSpecVersion(sbom.specVersion());
        row.setTool(sbom.tool().orElse(null));
        row.setComponentsCount(sbom.components().size());
        row.setCommit(accepted.commit());
        row.setBranch(accepted.branch());
        row.setDocumentSha256(accepted.documentSha256());
        row.setImportedAt(accepted.importedAt());
        row.setImportedBy(accepted.importedBy());
        row.setApiKeyId(accepted.apiKeyId());
        BuildSbomEntity saved = imports.save(row);
        listed.saveAll(sbom.components().stream().map(component -> {
            BuildSbomComponentEntity entity = new BuildSbomComponentEntity();
            entity.setImportId(saved.getId());
            entity.setName(component.name());
            entity.setVersion(component.version());
            entity.setPurl(component.purl());
            entity.setType(component.type());
            entity.setLicense(component.license());
            return entity;
        }).toList());
        Optional<Long> completed = completeNewest(accepted.repoId())
                .filter(scan -> saved.getId().equals(completedBy(scan)));
        return BuildSbomView.of(saved, completed.orElse(null));
    }

    /**
     * Completes the repository's newest completed scan with the newest build SBOM that may speak for it,
     * and answers that scan — empty when there is none, or when that scan kept no inventory: neither its
     * SBOM nor a component row.
     *
     * <p>Called again by the import after its commit: a scan whose ingestion read the imports just before
     * this one committed, and committed just after the import's own completion chose the scan before it,
     * would otherwise wait for the next import or scan. Asked when nothing moved, it writes nothing.
     */
    @Transactional
    public Optional<Long> completeNewest(long repositoryId) {
        NewestCompletedScanRow newest = scans.newestCompleted(List.of(new ScanTarget.Repository(repositoryId)))
                .get(new ScanTarget.Repository(repositoryId));
        // The SBOM stored, or the rows it left: the retention purges the payload and keeps the inventory,
        // which the component rules go on reading — a scan purged after indexing is completed as well.
        if (newest == null || !newest.sbomStored() && components.countByScanIdIn(List.of(newest.scanId())) == 0) {
            return Optional.empty();
        }
        complete(new ScanOrigin(newest.scanId(), repositoryId, null, newest.createdAt()));
        return Optional.of(newest.scanId());
    }

    /**
     * Completes one scan's inventory, just written by its scanner, with the newest build SBOM that may
     * speak for it — or gives back the scanner's rows where none may any more. In the caller's transaction:
     * the scan's ingestion, so the scan and its completed inventory commit together.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public void complete(ScanOrigin scan) {
        if (scan.repoId() == null) {
            return;
        }
        String branch = Optional.ofNullable(scans.labelsOf(List.of(scan.id())).get(scan.id()))
                .map(ScanCatalog.ScanLabel::branch).orElse(null);
        Optional<BuildSbomEntity> build = imports.newestFor(scan.repoId(), branch, PageRequest.of(0, 1)).stream()
                .findFirst();

        List<ComponentEntity> rows = components.lockScan(scan.id());
        List<ComponentEntity> fromBuild = rows.stream()
                .filter(row -> ComponentOrigin.ofStored(row.getOrigin()).fromBuild()).toList();
        if (build.isPresent() && !fromBuild.isEmpty()
                && fromBuild.stream().allMatch(row -> build.get().getId().equals(row.getBuildSbomId()))) {
            return;
        }
        if (build.isEmpty() && fromBuild.isEmpty()) {
            return;
        }

        // The scanner's inventory as it wrote it: what a previous SBOM added goes, what it completed is
        // given back its own version and purl.
        List<ComponentEntity> added = new ArrayList<>();
        List<ComponentEntity> scanner = new ArrayList<>();
        for (ComponentEntity row : rows) {
            switch (ComponentOrigin.ofStored(row.getOrigin())) {
                case BUILD -> added.add(row);
                case BOTH -> {
                    row.setVersion(row.getScannedVersion());
                    row.setPurl(row.getScannedPurl());
                    clearProvenance(row);
                    scanner.add(row);
                }
                case SCANNER -> scanner.add(row);
            }
        }
        components.deleteAll(added);
        if (build.isEmpty()) {
            components.saveAll(scanner);
            return;
        }

        List<BuildSbom.Component> stated = listed.findByImportIdOrderByIdAsc(build.get().getId()).stream()
                .map(row -> new BuildSbom.Component(row.getName(), row.getVersion(), row.getPurl(), row.getType(),
                        row.getLicense()))
                .toList();
        InventoryCompletion.Plan plan = InventoryCompletion.of(scanner.stream()
                .map(row -> new InventoryCompletion.Scanned(row.getId(), row.getName(), row.getVersion(), row.getPurl()))
                .toList(), stated);

        Map<Long, ComponentEntity> byId = scanner.stream().collect(Collectors.toMap(ComponentEntity::getId, row -> row));
        long importId = build.get().getId();
        for (InventoryCompletion.Completed completed : plan.completed()) {
            ComponentEntity row = byId.get(completed.id());
            row.setScannedVersion(row.getVersion());
            row.setScannedPurl(row.getPurl());
            row.setVersion(completed.version());
            row.setPurl(completed.purl());
            row.setOrigin(ComponentOrigin.BOTH.stored());
            row.setBuildSbomId(importId);
            row.setDeclaredLicense(completed.license());
        }
        components.saveAll(scanner);
        components.saveAll(plan.added().stream().map(component -> {
            ComponentEntity row = new ComponentEntity();
            row.setScanId(scan.id());
            row.setRepoId(scan.repoId());
            row.setScanCreatedAt(scan.createdAt());
            row.setName(component.name());
            row.setVersion(component.version());
            row.setPurl(component.purl());
            row.setType(component.type());
            // Unknown, not transitive: what the build's graph says of a component is not read here.
            row.setIsDirect(null);
            row.setOrigin(ComponentOrigin.BUILD.stored());
            row.setBuildSbomId(importId);
            row.setDeclaredLicense(component.license());
            return row;
        }).toList());
    }

    private static void clearProvenance(ComponentEntity row) {
        row.setOrigin(null);
        row.setBuildSbomId(null);
        row.setScannedVersion(null);
        row.setScannedPurl(null);
        row.setDeclaredLicense(null);
    }

    /** The import whose components a scan's inventory holds now, or null. */
    private Long completedBy(long scanId) {
        return components.findByScanId(scanId).stream()
                .map(ComponentEntity::getBuildSbomId)
                .filter(java.util.Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    /** How many imports one statement of the purge names. */
    private static final int PURGE_BATCH = 1_000;

    /** At most this many batches a turn: the next turn removes what this one left. */
    private static final int PURGE_BATCHES = 50;

    /**
     * The imports accepted before {@code cutoff}, and their components — the evidence window's purge.
     *
     * <p><b>The import, not what it gave.</b> The rows a scan was completed with stay with the scan, which
     * names the import as a reference only: a scan's inventory is what it was given. A repository whose
     * pipeline stopped sending SBOMs has its next scans read the scanner alone once the last one is past
     * the window — the build's word, kept no longer than the rest of the evidence.
     *
     * @return how many imports were removed
     */
    @Transactional
    public int purgeImportedBefore(Instant cutoff) {
        int purged = 0;
        for (int turn = 0; turn < PURGE_BATCHES; turn++) {
            List<Long> ids = imports.idsImportedBefore(cutoff, PageRequest.of(0, PURGE_BATCH));
            if (ids.isEmpty()) {
                break;
            }
            listed.deleteByImportIds(ids);
            purged += imports.deleteByIds(ids);
        }
        return purged;
    }

    /** A repository's latest imports, each with the newest scan it completed. The caller has checked the repository. */
    @Transactional(readOnly = true)
    public List<BuildSbomView> history(long repositoryId) {
        List<BuildSbomEntity> rows = imports.findByRepoIdOrderByIdDesc(repositoryId, PageRequest.of(0, HISTORY));
        Map<Long, Long> completed = new HashMap<>();
        if (!rows.isEmpty()) {
            for (Object[] row : components.newestScanCompletedBy(rows.stream().map(BuildSbomEntity::getId).toList())) {
                completed.put(((Number) row[0]).longValue(), ((Number) row[1]).longValue());
            }
        }
        return rows.stream().map(row -> BuildSbomView.of(row, completed.get(row.getId()))).toList();
    }
}

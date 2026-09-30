package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The inventory's backfill, against a database: it indexes the scans holding an SBOM that its own
 * table has no row for, and only those.
 *
 * <p>The selection used to be one statement in {@code scanning} reading {@code inventory}'s table;
 * it is now two questions, the scans' to {@link ScanCatalog} a page at a time and the components' to
 * this module. The page is what can go wrong — a first page of scans already indexed, and a backfill
 * that stops there finds nothing older — so these run with a page of two.
 */
@DisplayName("the inventory backfill, against a database")
class InventoryBackfillDatabaseTest extends VectispireContextTest {

    private static final String SBOM = "{\"artifacts\":[{\"name\":\"log4j-core\",\"version\":\"2.14.1\"}]}";

    private static final String PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1";

    private static final String WITH_PURL = "{\"artifacts\":[{\"name\":\"log4j-core\",\"version\":\"2.14.1\","
            + "\"purl\":\"" + PURL + "\"}]}";

    @Autowired
    private ScanRepository scanRows;

    @Autowired
    private ScanCatalog scans;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private ComponentInventory inventory;

    @Autowired
    private ObjectMapper json;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Test
    @DisplayName("indexes the scans with an SBOM and no components, past pages already indexed")
    void indexesWhatHasNoRows() {
        long oldest = scan(SBOM);
        long noSbom = scan(null);
        long older = scan(SBOM);
        // The two newest are indexed already: the first page holds nothing to do.
        long indexedA = indexed(scan(SBOM));
        long indexedB = indexed(scan(SBOM));

        int indexed = backfill().runOnce();

        assertThat(indexed).isEqualTo(2);
        assertThat(components.findByScanId(oldest)).extracting(ComponentEntity::getName).containsExactly("log4j-core");
        assertThat(components.findByScanId(older)).extracting(ComponentEntity::getName).containsExactly("log4j-core");
        assertThat(components.findByScanId(noSbom)).isEmpty();
        assertThat(components.findByScanId(indexedA)).hasSize(1);
        assertThat(components.findByScanId(indexedB)).hasSize(1);
        assertThat(backfill().runOnce()).as("converged").isZero();
    }

    @Test
    @DisplayName("each row carries its scan's target and creation instant, which every read of the inventory uses")
    void theRowsCarryTheirScansFacts() {
        Instant at = Instant.parse("2026-09-01T10:00:00.123Z");
        repository("ssh://git@example.invalid/unscanned.git");
        long repositoryId = repository("ssh://git@example.invalid/facts.git");
        ContainerEntity container = new ContainerEntity();
        container.setImageName("registry.invalid/facts");
        container.setTag("1.0");
        long containerId = containers.save(container).getId();
        // Two id spaces that could coincide: were they equal, a read of the wrong column would pass.
        assertThat(repositoryId).isNotEqualTo(containerId);
        long ofRepository = scan(WITH_PURL, repositoryId, null, at);
        long ofImage = scan(WITH_PURL, null, containerId, at.plusSeconds(60));

        backfill().runOnce();

        // Copied by ComponentInventory from the scan it was handed (V61): without them the search, the
        // version filter, the supply-chain figures and rule coverage would lose the row's target.
        assertThat(components.findByScanId(ofRepository)).singleElement().satisfies(row -> {
            assertThat(row.getRepoId()).isEqualTo(repositoryId);
            assertThat(row.getContainerId()).isNull();
            assertThat(row.getScanCreatedAt()).isEqualTo(at);
        });
        assertThat(components.findByScanId(ofImage)).singleElement().satisfies(row -> {
            assertThat(row.getRepoId()).isNull();
            assertThat(row.getContainerId()).isEqualTo(containerId);
            assertThat(row.getScanCreatedAt()).isEqualTo(at.plusSeconds(60));
        });
        assertThat(components.distinctRepositoriesWithComponents()).containsExactly(repositoryId);
        assertThat(components.distinctContainersWithComponents()).containsExactly(containerId);
        assertThat(components.distinctPurlsByTarget()).containsExactlyInAnyOrder(
                new Object[] {repositoryId, null, PURL}, new Object[] {null, containerId, PURL});
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private InventoryBackfill backfill() {
        return new InventoryBackfill(scans, components, inventory, json, 2);
    }

    private long scan(String sbom) {
        return scan(sbom, null, null, Instant.now());
    }

    private long scan(String sbom, Long repositoryId, Long containerId, Instant createdAt) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setContainerId(containerId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(createdAt);
        scan.setSbom(sbom);
        return scanRows.save(scan).getId();
    }

    private long indexed(long scanId) {
        ComponentEntity row = new ComponentEntity();
        row.setScanId(scanId);
        // The scan's target and instant, as ComponentInventory copies them (V61).
        ScanEntity scanOfRow = scanRows.findById(scanId).orElseThrow();
        row.setRepoId(scanOfRow.getRepoId());
        row.setContainerId(scanOfRow.getContainerId());
        row.setScanCreatedAt(scanOfRow.getCreatedAt());
        row.setName("already-there");
        components.saveAll(List.of(row));
        return scanId;
    }
}

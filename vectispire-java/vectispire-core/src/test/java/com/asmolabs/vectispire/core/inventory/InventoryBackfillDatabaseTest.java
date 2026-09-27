package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
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

    private InventoryBackfill backfill() {
        return new InventoryBackfill(scans, components, inventory, json, 2);
    }

    private long scan(String sbom) {
        ScanEntity scan = new ScanEntity();
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setSbom(sbom);
        return scanRows.save(scan).getId();
    }

    private long indexed(long scanId) {
        ComponentEntity row = new ComponentEntity();
        row.setScanId(scanId);
        row.setName("already-there");
        components.saveAll(List.of(row));
        return scanId;
    }
}

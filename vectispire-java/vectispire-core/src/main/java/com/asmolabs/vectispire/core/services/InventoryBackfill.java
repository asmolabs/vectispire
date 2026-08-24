package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.dependencies.DependencyGraph;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Components;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Fills the inventory of scans that ran before it existed.
 *
 * <p><b>Because the answer was already stored, and unreachable.</b> Every scan keeps its SBOM
 * whole, so the component list of every past scan is on disk; only the index was missing. Without
 * this, "which of our releases shipped log4j 2.14.1" would answer "no data" for the entire
 * history, which for that question is the same as answering wrongly — the releases somebody needs
 * to name are the old ones.
 *
 * <p><b>Idempotent and bounded.</b> It takes scans that have an SBOM and no components, a batch
 * at a time, so a large installation converges over several ticks instead of holding a
 * transaction open across ten thousand scans. A scan whose inventory is genuinely empty is
 * written as one row-less scan and reconsidered every pass — the cost of re-reading a few empty
 * documents is smaller than a marker column that could disagree with the table it describes.
 */
@Service
public class InventoryBackfill {

    private static final Logger log = LoggerFactory.getLogger(InventoryBackfill.class);

    /** Enough to converge quickly, small enough that one pass is never a long transaction. */
    private static final int BATCH = 50;

    private final Scans scans;
    private final Components components;
    private final ComponentInventory inventory;
    private final ObjectMapper json;

    public InventoryBackfill(Scans scans, Components components, ComponentInventory inventory, ObjectMapper json) {
        this.scans = scans;
        this.components = components;
        this.inventory = inventory;
        this.json = json;
    }

    /** @return how many scans were indexed this pass */
    @Transactional
    public int runOnce() {
        List<ScanEntity> pending = scans.findWithSbomButNoComponents(Limit.of(BATCH));
        if (pending.isEmpty()) {
            return 0;
        }

        int indexed = 0;
        for (ScanEntity scan : pending) {
            try {
                JsonNode sbom = json.readTree(scan.getSbom());
                inventory.record(scan.getId(), sbom, new DependencyGraph(sbom));
                indexed++;
            } catch (RuntimeException | com.fasterxml.jackson.core.JsonProcessingException unreadable) {
                // A stored payload that cannot be parsed is not worth failing the tick for, and
                // it will be retried next pass. Logged so a document that never indexes is
                // visible rather than silently absent from every search.
                log.warn("Inventory backfill: the SBOM of scan {} could not be read.", scan.getId());
            }
        }
        if (indexed > 0) {
            log.info("Inventory backfill: {} scan(s) indexed.", indexed);
        }
        return indexed;
    }
}

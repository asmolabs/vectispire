package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.dependencies.DependencyGraph;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanOrigin;
import com.asmolabs.vectispire.core.scanning.ScanView;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
 *
 * <p><b>Two questions, each to its owner.</b> One statement used to answer both — {@code scanning}
 * selected its scans with an SBOM and {@code not exists} a component row, reading {@code inventory}'s
 * table from a module that may not use it. {@link ScanCatalog} now hands the identifiers of the scans
 * holding an SBOM, a page at a time, newest first, and this module keeps those its own table has no
 * row for. A converged installation reads every page to find nothing, as the statement's anti-join
 * read every such scan; the pages carry identifiers only.
 */
@Service
public class InventoryBackfill {

    private static final Logger log = LoggerFactory.getLogger(InventoryBackfill.class);

    /** Enough to converge quickly, small enough that one pass is never a long transaction. */
    private static final int BATCH = 50;

    /** Identifiers per page: an in-list every engine takes, the SQLite fixture's included. */
    private static final int PAGE = 500;

    private final ScanCatalog scans;
    private final ComponentRepository components;
    private final ComponentInventory inventory;
    private final ObjectMapper json;
    private final int page;

    @Autowired
    public InventoryBackfill(ScanCatalog scans, ComponentRepository components, ComponentInventory inventory, ObjectMapper json) {
        this(scans, components, inventory, json, PAGE);
    }

    /** With a page small enough for a test to reach its second one. */
    InventoryBackfill(
            ScanCatalog scans, ComponentRepository components, ComponentInventory inventory, ObjectMapper json, int page) {
        this.scans = scans;
        this.components = components;
        this.inventory = inventory;
        this.json = json;
        this.page = page;
    }

    /** @return how many scans were indexed this pass */
    @Transactional
    public int runOnce() {
        List<ScanView> pending = scans.scans(unindexed());
        if (pending.isEmpty()) {
            return 0;
        }

        int indexed = 0;
        for (ScanView scan : pending) {
            try {
                JsonNode sbom = json.readTree(scan.sbom());
                inventory.record(ScanOrigin.of(scan), sbom, new DependencyGraph(sbom));
                indexed++;
            } catch (RuntimeException | com.fasterxml.jackson.core.JsonProcessingException unreadable) {
                // A stored payload that cannot be parsed is not worth failing the tick for, and
                // it will be retried next pass. Logged so a document that never indexes is
                // visible rather than silently absent from every search.
                log.warn("Inventory backfill: the SBOM of scan {} could not be read.", scan.id());
            }
        }
        if (indexed > 0) {
            log.info("Inventory backfill: {} scan(s) indexed.", indexed);
        }
        return indexed;
    }

    /** Up to a batch of the newest scans holding an SBOM that have no component row. */
    private List<Long> unindexed() {
        List<Long> pending = new ArrayList<>();
        long before = Long.MAX_VALUE;
        while (pending.size() < BATCH) {
            List<Long> ids = scans.idsWithSbomBefore(before, page);
            if (ids.isEmpty()) {
                break;
            }
            Set<Long> indexed = new HashSet<>(components.indexedAmong(ids));
            ids.stream()
                    .filter(id -> !indexed.contains(id))
                    .limit(BATCH - pending.size())
                    .forEach(pending::add);
            before = ids.getLast();
        }
        return pending;
    }
}

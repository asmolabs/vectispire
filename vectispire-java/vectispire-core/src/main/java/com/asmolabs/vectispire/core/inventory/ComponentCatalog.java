package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.sbom.ComponentOrigin;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The components the inventory holds for given scans, as views — what a checklist's component rule
 * reads of a repository's newest analysed SBOM (decision 0032 §6), without reaching this module's
 * repository: the scanner's rows, completed by the build SBOM where one completed the scan (decision
 * 0039) — the same rows every other reader of the inventory reads.
 *
 * <p><b>The caller has already decided what may be read.</b> These answer for the scans they are
 * given: a checklist names the scans of a project it has refused unless wholly visible. A route never
 * calls this — the inventory's own routes resolve a {@code Visibility}.
 *
 * <p><b>A thousand scans per statement</b>: the identifiers come from a project's repositories, which
 * the data sizes, and the PostgreSQL driver refuses a statement past 65,535 bind parameters.
 */
@Service
@Transactional(readOnly = true)
public class ComponentCatalog {

    static final int BATCH = 1_000;

    private final ComponentRepository components;

    public ComponentCatalog(ComponentRepository components) {
        this.components = components;
    }

    /**
     * A component as the scan's inventory lists it: the version is the one stored, exactly — no ordering
     * is applied — and, where a build SBOM completed the scan, the build's (decision 0039).
     *
     * @param origin who listed it: the scanner, the build's SBOM, or both
     */
    public record Component(long scanId, String name, String version, String purl, String type, ComponentOrigin origin) {}

    /**
     * Each scan's components; a scan the inventory holds nothing for is absent from the map — one whose
     * SBOM listed none, or one not indexed yet, which the caller must not read as "listed none" unless
     * the scan is known to have stored its SBOM.
     */
    public Map<Long, List<Component>> componentsOf(Collection<Long> scanIds) {
        List<Long> distinct = new ArrayList<>(new LinkedHashSet<>(scanIds));
        Map<Long, List<Component>> byScan = new HashMap<>();
        for (int from = 0; from < distinct.size(); from += BATCH) {
            components.findByScanIdIn(distinct.subList(from, Math.min(distinct.size(), from + BATCH))).forEach(row ->
                    byScan.computeIfAbsent(row.getScanId(), id -> new ArrayList<>())
                            .add(new Component(row.getScanId(), row.getName(), row.getVersion(), row.getPurl(), row.getType(),
                                    ComponentOrigin.ofStored(row.getOrigin()))));
        }
        Map<Long, List<Component>> answer = new HashMap<>();
        byScan.forEach((scan, listed) -> answer.put(scan, List.copyOf(listed)));
        return Map.copyOf(answer);
    }
}

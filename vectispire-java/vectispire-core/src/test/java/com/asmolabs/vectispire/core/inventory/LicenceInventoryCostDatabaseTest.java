package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.inventory.LicenceEstate.Reads;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import jakarta.persistence.EntityManagerFactory;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * What the licence screen's routes read for the whole estate — {@code GET /api/v1/licenses/inventory},
 * {@code /summary} and {@code /conflicts} with no target, and the evidence bundle's summary.
 *
 * <p><b>The defect this closes.</b> Each read the estate's inventory — every scan with its whole row,
 * every component row as an entity, every licence finding — and narrowed afterwards: 105,523 entities
 * and 340 to 650 ms a call on {@link LicenceEstate} with 250 components an SBOM and a scan attached
 * to no target, on MySQL, for an administrator and for a reader granted five targets alike. Measured
 * again after:
 * <ul>
 *   <li>the summaries are counts by licence, which the tallies hold: no scan, component or finding
 *       read, warm, about 20 ms;
 *   <li>a restricted reader's inventory is read from their targets' scans: ten scans, their component
 *       rows and their findings, about 25 ms;
 *   <li>an administrator's inventory and conflicts read the history, since they list a row per
 *       component of every scan: every scan's SBOM and every component row, as the columns the
 *       inventory needs rather than as entities — 220 to 350 ms. The statements stay a handful.
 * </ul>
 * And since 1.0.0-rc.1 the inventory and the conflicts asked for no target are served from the entries
 * the tallies' recount keeps: the history is read once per target and per change of its scans, and a
 * warm administrator's read reads no scan, no component and no finding — 230 to 280 ms became 35 to
 * 50 ms; a restricted reader's, 15 ms before, about 20 ms, the census of the estate now read first.
 * The timings are a laptop's and are not asserted; the rows read are.
 *
 * <p>One case, in order, because the tallies outlive a case: the singleton keeps them.
 */
@DisplayName("the cost of the licence screen's estate-wide routes")
class LicenceInventoryCostDatabaseTest extends VectispireContextTest {

    private static final int SCANS_PER_TARGET = LicenceEstate.SCANS_PER_TARGET;
    private static final int ROWS_PER_SCAN = LicenceEstate.ROWS_PER_SCAN;

    /** A summary off the tallies, warm: the census, the SBOM scans, their component lookup, the policy. */
    private static final int MAX_SUMMARY_STATEMENTS = 5;

    /**
     * The inventory's statements served from memory: the census, the SBOM scans, their component lookup
     * and the build completions — the tallies' stamp — then the policy and the targets' names.
     */
    private static final int MAX_INVENTORY_STATEMENTS = 7;

    /**
     * And when some targets are counted again: their scans by repository and by image, one component
     * lookup and one finding lookup per thousand scans, and the scans attached to no target.
     */
    private static final int MAX_RECOUNT_STATEMENTS = MAX_INVENTORY_STATEMENTS + 5;

    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private LicenseGovernanceService licences;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Test
    @DisplayName("a restricted reader's inventory reads their scans, a summary reads none once counted")
    void readsWhatTheRouteNeeds() {
        LicenceEstate seeded = new LicenceEstate(repositories, containers, scans, jdbc);
        List<ScanTarget> estate = seeded.seed();
        seeded.sbomScan(null, 3);
        // Of a repository the reader is not given, though it names an image they are.
        ScanTarget.Container image = (ScanTarget.Container) estate.get(LicenceEstate.REPOSITORIES);
        seeded.sbomScanOfBoth((ScanTarget.Repository) estate.get(10), image, 2);
        int scanned = estate.size() * SCANS_PER_TARGET + 2;
        List<ScanTarget> granted = new ArrayList<>(estate.subList(0, 5));
        granted.add(image);
        Visibility restricted = Visibility.only(granted);

        // The inventory of a reader granted six targets, cold: their scans, and nobody else's. The scan
        // naming their image and another's repository comes back with the image's and is left there, its
        // components and findings unread: every entry it makes is the repository's.
        Reads theirs = read(() -> licences.getInventory(restricted, null, null));
        assertThat(theirs.scans()).isEqualTo(6 * SCANS_PER_TARGET + 1);
        assertThat(theirs.components()).isEqualTo(6 * SCANS_PER_TARGET * ROWS_PER_SCAN);
        assertThat(theirs.findings()).isEqualTo(6 * SCANS_PER_TARGET);
        assertThat(theirs.statements()).isLessThanOrEqualTo(MAX_RECOUNT_STATEMENTS);

        // The administrator's, cold: the history of every target not counted yet — no row as an entity,
        // and statements that do not follow the estate.
        Reads cold = read(() -> licences.getInventory(Visibility.everything(), null, null));
        assertThat(cold.scans()).isEqualTo(scanned - 6 * SCANS_PER_TARGET);
        assertThat(cold.components()).isEqualTo((long) (scanned - 6 * SCANS_PER_TARGET) * ROWS_PER_SCAN);
        assertThat(cold.statements()).isLessThanOrEqualTo(MAX_RECOUNT_STATEMENTS);

        // Warm, the inventory and its conflicts read no scan, no component and no finding.
        for (Runnable warm : List.<Runnable>of(
                () -> licences.getInventory(Visibility.everything(), null, null),
                () -> licences.getInventory(Visibility.everything(), null, null, 50, 100),
                () -> licences.evaluateConflicts(Visibility.everything(), null, null, true),
                () -> licences.getInventory(restricted, null, null))) {
            Reads served = read(warm);
            assertThat(served.scans()).isZero();
            assertThat(served.components()).isZero();
            assertThat(served.findings()).isZero();
            assertThat(served.statements()).isLessThanOrEqualTo(MAX_INVENTORY_STATEMENTS);
        }

        // The estate's summary, off the tallies the inventory's read counted.
        Reads summary = read(() -> licences.getSummary(Visibility.everything(), null, null));
        assertThat(summary.scans()).isZero();
        assertThat(summary.components()).isZero();
        assertThat(summary.findings()).isZero();
        assertThat(summary.statements()).isLessThanOrEqualTo(MAX_SUMMARY_STATEMENTS);

        // The evidence bundle's, for the restricted reader, off what the administrator's read kept.
        Reads evidence = read(() -> licences.getSummary(restricted));
        assertThat(evidence.scans()).isZero();
        assertThat(evidence.components()).isZero();
        assertThat(evidence.statements()).isLessThanOrEqualTo(MAX_SUMMARY_STATEMENTS);

        // A new scan of one target: the inventory reads that target's scans again, and only those.
        seeded.sbomScan(estate.get(42), 3);
        assertThat(read(() -> licences.getInventory(Visibility.everything(), null, null)).scans())
                .isEqualTo(SCANS_PER_TARGET + 1);
        assertThat(read(() -> licences.getSummary(Visibility.everything(), null, null)).scans()).isZero();
    }

    private Reads read(Runnable route) {
        return Reads.of(entityManagerFactory, route);
    }
}

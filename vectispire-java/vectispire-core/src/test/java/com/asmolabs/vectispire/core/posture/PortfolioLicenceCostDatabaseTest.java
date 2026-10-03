package com.asmolabs.vectispire.core.posture;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.inventory.LicenceEstate;
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
 * The portfolio scorecard ({@code GET /api/v1/scorecards/global}) reads the licence tallies the
 * ranking keeps, and must not read the estate's history to do it.
 *
 * <p><b>The defect this closes.</b> {@code getGlobalScorecard} took its licence term from the estate's
 * inventory, narrowed to the reader afterwards: every scan with its SBOM, every component row and
 * every licence finding of the deployment, for an administrator and for a reader granted five targets
 * alike. Measured on {@link LicenceEstate} with 250 components an SBOM and a scan attached to no
 * target, on MySQL: 425 to 840 ms and 105,523 entities a call for either reader; with the tallies, warm,
 * 40 to 55 ms and no scan, component or finding — the targets' names and the counts the stamps are
 * made of. Cold, the reader's first call counts what it may see and nothing else. The timings are a
 * laptop's and are not asserted; the rows read are.
 *
 * <p>One case, in order, because the tallies outlive a case: the singleton keeps them.
 */
@DisplayName("the cost of the portfolio scorecard's licence term")
class PortfolioLicenceCostDatabaseTest extends VectispireContextTest {

    private static final int SCANS_PER_TARGET = LicenceEstate.SCANS_PER_TARGET;
    private static final int ROWS_PER_SCAN = LicenceEstate.ROWS_PER_SCAN;

    /**
     * The portfolio's statements, warm: the targets, the grading counts, the completed scans' targets,
     * the overdue count, the census, the scans holding an SBOM, one component lookup per thousand of
     * those, and the policy. Thirteen were measured.
     */
    private static final int MAX_STATEMENTS = 15;

    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private SecurityScorecardService scorecards;

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
    @DisplayName("reads the scans of what moved and the reader may see, attached to a target or to none")
    void readsWhatMoved() {
        LicenceEstate seeded = new LicenceEstate(repositories, containers, scans, jdbc);
        List<ScanTarget> estate = seeded.seed();
        seeded.sbomScan(null, 3);
        // Of a repository the reader is not given, though it names an image they are.
        ScanTarget.Container image = (ScanTarget.Container) estate.get(LicenceEstate.REPOSITORIES);
        seeded.sbomScanOfBoth((ScanTarget.Repository) estate.get(10), image, 2);
        List<ScanTarget> granted = new ArrayList<>(estate.subList(0, 5));
        granted.add(image);
        Visibility restricted = Visibility.only(granted);

        // Cold, for a reader granted six targets: theirs are counted, the scan attached to none is not
        // theirs to count, and nobody else's is read. The scan naming their image and another's
        // repository comes back with the image's, and is left there: it is the repository's.
        Reads cold = load(restricted);
        assertThat(cold.scans()).isEqualTo(6 * SCANS_PER_TARGET + 1);
        assertThat(cold.components()).isEqualTo(6 * SCANS_PER_TARGET * ROWS_PER_SCAN);
        assertThat(cold.findings()).isEqualTo(6 * SCANS_PER_TARGET);

        // The administrator's first call counts the others, the scan naming both with its repository and
        // the scan attached to none, and only them.
        int others = (estate.size() - 6) * SCANS_PER_TARGET + 2;
        Reads first = load(Visibility.everything());
        assertThat(first.scans()).isEqualTo(others);
        assertThat(first.components()).isEqualTo((long) others * ROWS_PER_SCAN);

        // Warm: nothing of the history is read, and the statements do not follow the estate.
        Reads warm = load(Visibility.everything());
        assertThat(warm.scans()).isZero();
        assertThat(warm.components()).isZero();
        assertThat(warm.findings()).isZero();
        assertThat(warm.statements()).isLessThanOrEqualTo(MAX_STATEMENTS);
        Reads warmRestricted = load(restricted);
        assertThat(warmRestricted.scans()).isZero();
        assertThat(warmRestricted.components()).isZero();
        assertThat(warmRestricted.statements()).isLessThanOrEqualTo(MAX_STATEMENTS);

        // A new scan attached to no target: those scans are read again, for the administrator only.
        seeded.sbomScan(null, 1);
        assertThat(load(restricted).scans()).isZero();
        Reads moved = load(Visibility.everything());
        assertThat(moved.scans()).isEqualTo(2);
        assertThat(moved.components()).isEqualTo(2 * ROWS_PER_SCAN);

        // A new scan of one of the reader's targets: that target's scans, and only those.
        seeded.sbomScan(estate.get(3), 2);
        assertThat(load(restricted).scans()).isEqualTo(SCANS_PER_TARGET + 1);
        assertThat(load(Visibility.everything()).scans()).isZero();
    }

    private Reads load(Visibility allowed) {
        return Reads.of(entityManagerFactory, () -> scorecards.getGlobalScorecard(allowed));
    }
}

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
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The dashboard's ranking reads each target's licence violations, and must not read the estate's
 * history to do it.
 *
 * <p><b>The defect this closes.</b> {@code SecurityScorecardService.gradeEach} took the licence term
 * from the estate's inventory: every scan row with its payloads, every SBOM parsed, every component
 * row of every scan — on every load of the home page, for an administrator and for a reader granted
 * five targets alike, since the narrowing came after the read. Measured on this estate (two hundred
 * targets, two scans each, 250 components an SBOM) on MySQL, a load of the posture page cost about
 * 420 ms and 105,201 entities for either reader; with the tallies, 30 to 50 ms and 201 entities (the
 * targets' names) for the administrator, about 25 ms and 6 for the restricted reader. The timings
 * are a laptop's and are not asserted; the scans and component rows read are, being what grows with
 * the history — as entities or as the columns the inventory selects, which {@link Reads} counts alike.
 *
 * <p>One case, in order, because the tallies outlive a case: the singleton keeps them, and what each
 * step may read depends on what the step before it kept.
 */
@DisplayName("the cost of the dashboard's ranking")
class RankingLicenceCostDatabaseTest extends VectispireContextTest {

    private static final int SCANS_PER_TARGET = LicenceEstate.SCANS_PER_TARGET;
    private static final int ROWS_PER_SCAN = LicenceEstate.ROWS_PER_SCAN;

    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private DashboardQueryService dashboard;

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
    @DisplayName("reads the scans of the targets that moved, and of no other")
    void readsWhatMoved() {
        LicenceEstate seeded = new LicenceEstate(repositories, containers, scans, jdbc);
        List<ScanTarget> estate = seeded.seed();
        Visibility restricted = Visibility.only(estate.subList(0, 5));

        // Cold, for a reader granted five targets: theirs are counted, and nobody else's are read.
        Reads cold = load(restricted);
        assertThat(cold.scans()).isEqualTo(5 * SCANS_PER_TARGET);
        assertThat(cold.components()).isEqualTo(5 * SCANS_PER_TARGET * ROWS_PER_SCAN);

        // The administrator's first load counts the others, and only them.
        assertThat(load(Visibility.everything()).scans()).isEqualTo((estate.size() - 5) * SCANS_PER_TARGET);

        // Warm: nothing of the history is read, and the statements do not follow the estate.
        Reads warm = load(Visibility.everything());
        assertThat(warm.scans()).isZero();
        assertThat(warm.components()).isZero();
        assertThat(warm.findings()).isZero();
        assertThat(warm.statements()).isLessThanOrEqualTo(MAX_STATEMENTS);
        assertThat(load(restricted).scans()).isZero();

        // A new scan of one target: that target's scans are read again, and only those.
        seeded.sbomScan(estate.get(42), 3);
        Reads moved = load(Visibility.everything());
        assertThat(moved.scans()).isEqualTo(SCANS_PER_TARGET + 1);
        assertThat(moved.components()).isEqualTo((SCANS_PER_TARGET + 1) * ROWS_PER_SCAN);
    }

    /**
     * The posture page's statements, warm: the dashboard's own reads, the census, the scans holding an
     * SBOM, one component lookup per thousand of those, and the policy. Ten were measured.
     */
    private static final int MAX_STATEMENTS = 12;

    private Reads load(Visibility allowed) {
        return Reads.of(entityManagerFactory, () -> dashboard.postureAnalytics(30, allowed));
    }
}

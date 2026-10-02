package com.asmolabs.vectispire.core.posture;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import jakarta.persistence.EntityManagerFactory;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
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
 * are a laptop's and are not asserted; the entities are, being what grows with the history.
 *
 * <p>One case, in order, because the tallies outlive a case: the singleton keeps them, and what each
 * step may read depends on what the step before it kept.
 */
@DisplayName("the cost of the dashboard's ranking")
class RankingLicenceCostDatabaseTest extends VectispireContextTest {

    private static final int REPOSITORIES = 160;
    private static final int CONTAINERS = 40;
    private static final int SCANS_PER_TARGET = 2;
    private static final int COMPONENTS = 100;

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
        List<ScanTarget> estate = seed();
        Visibility restricted = Visibility.only(estate.subList(0, 5));

        // Cold, for a reader granted five targets: theirs are counted, and nobody else's are read.
        Reads cold = load(restricted);
        assertThat(cold.scans()).isEqualTo(5 * SCANS_PER_TARGET);
        assertThat(cold.components()).isEqualTo(5 * SCANS_PER_TARGET * (COMPONENTS + 10));

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
        sbomScan(estate.get(42), 3);
        Reads moved = load(Visibility.everything());
        assertThat(moved.scans()).isEqualTo(SCANS_PER_TARGET + 1);
        assertThat(moved.components()).isEqualTo((SCANS_PER_TARGET + 1) * (COMPONENTS + 10));
    }

    /**
     * The posture page's statements, warm: the dashboard's own reads, the census, the scans holding an
     * SBOM, one component lookup per thousand of those, and the policy. Ten were measured.
     */
    private static final int MAX_STATEMENTS = 12;

    private record Reads(long scans, long components, long findings, long statements) {}

    private Reads load(Visibility allowed) {
        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();
        dashboard.postureAnalytics(30, allowed);
        return new Reads(
                statistics.getEntityStatistics(ScanEntity.class.getName()).getLoadCount(),
                statistics.getEntityStatistics(ComponentEntity.class.getName()).getLoadCount(),
                statistics.getEntityStatistics(FindingEntity.class.getName()).getLoadCount(),
                statistics.getPrepareStatementCount());
    }

    private List<ScanTarget> seed() {
        List<ScanTarget> estate = new ArrayList<>();
        for (int index = 0; index < REPOSITORIES; index++) {
            RepositoryEntity repository = new RepositoryEntity();
            repository.setName("corp/r" + index);
            repository.setUrl("https://example.invalid/corp/r" + index + ".git");
            repository.setBranch("main");
            estate.add(new ScanTarget.Repository(repositories.save(repository).getId()));
        }
        for (int index = 0; index < CONTAINERS; index++) {
            ContainerEntity container = new ContainerEntity();
            container.setImageName("registry.example.invalid/c" + index);
            container.setTag("1.0");
            estate.add(new ScanTarget.Container(containers.save(container).getId()));
        }
        int ordinal = 0;
        for (ScanTarget target : estate) {
            for (int scan = 0; scan < SCANS_PER_TARGET; scan++) {
                sbomScan(target, ordinal++ % 7);
            }
        }
        return estate;
    }

    private void sbomScan(ScanTarget target, int forbidden) {
        StringBuilder sbom = new StringBuilder("{\"artifacts\":[");
        for (int index = 0; index < COMPONENTS; index++) {
            if (index > 0) {
                sbom.append(',');
            }
            String licence = index < forbidden ? "GPL-3.0-only" : "MIT";
            sbom.append("{\"name\":\"pkg").append(index).append("\",\"version\":\"1.").append(index)
                    .append("\",\"purl\":\"pkg:npm/pkg").append(index).append("@1.").append(index)
                    .append("\",\"licenses\":[{\"value\":\"").append(licence).append("\"}]}");
        }
        sbom.append("]}");
        ScanEntity scan = new ScanEntity();
        Long repoId = target instanceof ScanTarget.Repository r ? r.id() : null;
        Long containerId = target instanceof ScanTarget.Container c ? c.id() : null;
        scan.setRepoId(repoId);
        scan.setContainerId(containerId);
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(Instant.now());
        scan.setSbom(sbom.toString());
        long scanId = scans.save(scan).getId();

        List<Object[]> rows = new ArrayList<>();
        for (int index = 0; index < COMPONENTS + 10; index++) {
            rows.add(new Object[] {scanId, repoId, containerId, Timestamp.from(Instant.now()),
                "pkg" + index, "1." + index, "pkg:npm/pkg" + index + "@1." + index, "library"});
        }
        jdbc.batchUpdate("insert into t_component (scan_id, repo_id, container_id, scan_created_at, name, version, purl, type)"
                + " values (?, ?, ?, ?, ?, ?, ?, ?)", rows);
        jdbc.update("insert into t_finding (scan_id, type, source, package_name, package_version, identifier, is_kev, created_at, reachability)"
                + " values (?, 'license', 'trivy', 'lic-only', '2.0', 'AGPL-3.0-only', false, ?, 'UNKNOWN')",
                scanId, Timestamp.from(Instant.now()));
    }
}

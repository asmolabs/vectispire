package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Comparing two scans of one target must not read the estate's history.
 *
 * <p><b>The defect this closes.</b> {@code diffLatest} called {@code scans.findAll()}, then
 * filtered, sorted and kept two rows in Java. Every scan row in the deployment was therefore
 * loaded as an entity to retain two identifiers — and a scan row carries its whole SBOM payload,
 * megabytes apiece. Asking for one repository's diff read every other repository's SBOM.
 *
 * <p><b>Why a dedicated case rather than the sweep.</b> {@code ReadCostSweepTest} walks the whole
 * GET surface and should have caught it; it excludes {@code /api/v1/sbom/diff/latest} by name,
 * because the route answers 404 until the fixture has two scans to compare. The exclusion was
 * reasonable and it is what let the defect through: a route that cannot be measured where
 * everything else is measured needs a measurement of its own, without which "not measured" reads
 * as "measured and acceptable".
 */
@DisplayName("the cost of the SBOM diff")
class SbomDiffCostDatabaseTest extends VectispireContextTest {

    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private SbomDiffService sbomDiff;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    private long target;

    @BeforeEach
    void seed() {
        target = repository("https://example.invalid/target.git", "target");
        scan(target);
        scan(target);
    }

    @Test
    @DisplayName("ne suit pas le nombre de scans des autres cibles")
    void theCostDoesNotFollowTheEstate() {
        long stranger = repository("https://example.invalid/stranger.git", "stranger");
        for (int index = 0; index < 200; index++) {
            scan(stranger);
        }

        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();

        assertThat(sbomDiff.diffLatest(target, null)).isPresent();

        // Two hundred scans that are foreign to the question asked. The threshold is low and
        // deliberately not zero: the diff then loads the two scans it compares and their findings,
        // which is the work asked for. What is forbidden is for the estate to enter the count.
        assertThat(statistics.getEntityLoadCount())
                .as("comparing two scans of one repository must not read the others'")
                .isLessThan(50);
    }

    @Test
    @DisplayName("a single scan compares with itself, rather than answering \"nothing\"")
    void oneScanIsStillAnAnswer() {
        long lonely = repository("https://example.invalid/lonely.git", "lonely");
        scan(lonely);

        // "Nothing changed" and "no data" look alike on screen and do not mean the same thing; the
        // second reads as a failure.
        assertThat(sbomDiff.diffLatest(lonely, null)).isPresent();
    }

    @Test
    @DisplayName("une cible sans scan ne rend rien, et sans lire quoi que ce soit")
    void noScanAtAll() {
        long empty = repository("https://example.invalid/empty.git", "empty");

        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();

        assertThat(sbomDiff.diffLatest(empty, null)).isEmpty();
        assertThat(statistics.getEntityLoadCount())
                .as("no scan to compare is answered by one query, not by a read of the estate")
                .isZero();
    }

    private long repository(String url, String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private void scan(long repoId) {
        ScanEntity entity = new ScanEntity();
        entity.setRepoId(repoId);
        entity.setStatus(ScanStatus.COMPLETED.wireName());
        entity.setBranch("main");
        entity.setCreatedAt(Instant.now());
        scans.save(entity);
    }
}

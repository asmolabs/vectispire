package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
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
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The estate the licence cost tests read: two hundred targets of two scans, each scan an SBOM of
 * {@link #COMPONENTS} artifacts, ten component rows more than the SBOM declares, and a licence finding.
 *
 * <p>One estate for the ranking, the portfolio's scorecard and the licence routes, so that their
 * measurements describe the same history. The figures in their javadocs were measured with 250
 * components an SBOM; the suite seeds fewer, since what is asserted is what a read loads, not how
 * long it takes.
 */
public final class LicenceEstate {

    public static final int REPOSITORIES = 160;
    public static final int CONTAINERS = 40;
    public static final int SCANS_PER_TARGET = 2;
    public static final int COMPONENTS = 100;

    /** The component rows of one scan: the SBOM's artifacts and ten it does not declare. */
    public static final int ROWS_PER_SCAN = COMPONENTS + 10;

    private final GitRepositoryRepository repositories;
    private final ContainerRepository containers;
    private final ScanRepository scans;
    private final JdbcTemplate jdbc;

    public LicenceEstate(
            GitRepositoryRepository repositories, ContainerRepository containers, ScanRepository scans, JdbcTemplate jdbc) {
        this.repositories = repositories;
        this.containers = containers;
        this.scans = scans;
        this.jdbc = jdbc;
    }

    /**
     * What one read loaded and how many statements it prepared.
     *
     * <p>A scan or a component row counts whether it came as an entity or as the columns the
     * inventory selects ({@code ScanCatalog.ScanSbom}, {@code ComponentName}): the projections are not
     * entities, and counting entities alone would call a read of the whole history free.
     *
     * @param scans scans read with their SBOM
     * @param components component rows read
     * @param findings findings loaded
     */
    public record Reads(long scans, long components, long findings, long statements) {

        /** Statistics cleared, the read run, its counts taken. */
        public static Reads of(EntityManagerFactory factory, Runnable read) {
            Statistics statistics = factory.unwrap(SessionFactory.class).getStatistics();
            statistics.clear();
            read.run();
            return new Reads(
                    statistics.getEntityStatistics(ScanEntity.class.getName()).getLoadCount()
                            + rowsOf(statistics, ", s.sbom from ScanEntity"),
                    statistics.getEntityStatistics(ComponentEntity.class.getName()).getLoadCount()
                            + rowsOf(statistics, "ComponentName("),
                    statistics.getEntityStatistics(FindingEntity.class.getName()).getLoadCount(),
                    statistics.getPrepareStatementCount());
        }

        /** The rows the queries whose text holds {@code marker} returned. */
        private static long rowsOf(Statistics statistics, String marker) {
            long rows = 0;
            for (String query : statistics.getQueries()) {
                if (query.contains(marker)) {
                    rows += statistics.getQueryStatistics(query).getExecutionRowCount();
                }
            }
            return rows;
        }
    }

    /** The targets, repositories first, each holding {@link #SCANS_PER_TARGET} scans. */
    public List<ScanTarget> seed() {
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

    /**
     * A completed scan of {@code target} — of none when null — whose first {@code forbidden} artifacts
     * declare GPL-3.0 and the others MIT, with its component rows and an AGPL licence finding.
     */
    public long sbomScan(ScanTarget target, int forbidden) {
        return sbomScan(
                target instanceof ScanTarget.Repository r ? r.id() : null,
                target instanceof ScanTarget.Container c ? c.id() : null,
                forbidden);
    }

    /**
     * A scan naming a repository and an image, as {@link #sbomScan(ScanTarget, int)} makes them: the
     * repository's, whichever target it is read for.
     */
    public long sbomScanOfBoth(ScanTarget.Repository repository, ScanTarget.Container container, int forbidden) {
        return sbomScan(repository.id(), container.id(), forbidden);
    }

    private long sbomScan(Long repoId, Long containerId, int forbidden) {
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
        scan.setRepoId(repoId);
        scan.setContainerId(containerId);
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(Instant.now());
        scan.setSbom(sbom.toString());
        long scanId = scans.save(scan).getId();

        List<Object[]> rows = new ArrayList<>();
        for (int index = 0; index < ROWS_PER_SCAN; index++) {
            rows.add(new Object[] {scanId, repoId, containerId, Timestamp.from(Instant.now()),
                "pkg" + index, "1." + index, "pkg:npm/pkg" + index + "@1." + index, "library"});
        }
        jdbc.batchUpdate("insert into t_component (scan_id, repo_id, container_id, scan_created_at, name, version, purl, type)"
                + " values (?, ?, ?, ?, ?, ?, ?, ?)", rows);
        jdbc.update("insert into t_finding (scan_id, type, source, package_name, package_version, identifier, is_kev, created_at, reachability)"
                + " values (?, 'license', 'trivy', 'lic-only', '2.0', 'AGPL-3.0-only', false, ?, 'UNKNOWN')",
                scanId, Timestamp.from(Instant.now()));
        return scanId;
    }
}

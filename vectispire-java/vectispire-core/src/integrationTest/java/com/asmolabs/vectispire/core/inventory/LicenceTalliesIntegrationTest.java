package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.LongStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The licence tallies' reads on a real engine: the scans' census — a {@code sum} over a {@code case}
 * testing a large-object column for null, grouped by target and status — the scans holding an SBOM,
 * the recount's lookup of the scans of the targets that moved and of those attached to none, and the
 * columns the inventory selects instead of the rows.
 *
 * <p>The recount is handed seventy thousand repositories and seventy thousand images, one bind
 * parameter each, which the catalogue asks a thousand at a time. That limit is <b>PostgreSQL's
 * alone</b> — the driver refuses a statement past 65,535 parameters; MySQL's client-side statements
 * accepted such a statement when measured — so a green run on MySQL proves the queries, not the
 * batching.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the licence tallies, on the engine")
class LicenceTalliesIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    /** Seventy thousand identifiers no row carries — past the PostgreSQL driver's 65,535. */
    private static final List<Long> NOBODY = LongStream.rangeClosed(9_000_000, 9_070_000).boxed().toList();

    @BeforeAll
    static void start() {
        CONTAINER.start();
    }

    @AfterAll
    static void stop() {
        CONTAINER.stop();
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private ScanCatalog catalog;

    @Autowired
    private LicenseGovernanceService licences;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("the census, the scans holding an SBOM, the recount past the bind limit, and the count the inventory gives")
    void onTheEngine() {
        ScanTarget.Repository repository = new ScanTarget.Repository(repository());
        long completed = scan(repository.id(), null, ScanStatus.COMPLETED,
                "{\"artifacts\":[{\"name\":\"a\",\"version\":\"1\",\"licenses\":[{\"value\":\"GPL-3.0-only\"}]}]}");
        component(completed, "a", "1");
        component(completed, "b", "1");
        licenceFinding(completed, "c", "1", "AGPL-3.0-only");
        long failed = scan(repository.id(), null, ScanStatus.FAILED, "{\"artifacts\":[]}");
        long pending = scan(repository.id(), null, ScanStatus.PENDING, null);
        ScanTarget.Container image = new ScanTarget.Container(container());
        long imageScan = scan(null, image.id(), ScanStatus.COMPLETED,
                "{\"artifacts\":[{\"name\":\"i\",\"version\":\"1\",\"licenses\":[{\"value\":\"MIT\"}]}]}");

        // Attached to neither target: a census of its own, and read on its own.
        long untargeted = scan(null, null, ScanStatus.COMPLETED,
                "{\"artifacts\":[{\"name\":\"g\",\"version\":\"1\",\"licenses\":[{\"value\":\"GPL-2.0-only\"}]}]}");

        ScanCatalog.Census all = catalog.census();
        ScanCatalog.ScanCensus census = all.byTarget().get(repository);
        assertThat(census.scans()).isEqualTo(3);
        assertThat(census.newestId()).isEqualTo(Math.max(completed, Math.max(failed, pending)));
        assertThat(census.withSbom()).isEqualTo(2);
        assertThat(census.byStatus()).containsOnly(
                Map.entry(ScanStatus.COMPLETED.wireName(), 1L),
                Map.entry(ScanStatus.FAILED.wireName(), 1L),
                Map.entry(ScanStatus.PENDING.wireName(), 1L));
        assertThat(all.byTarget().get(image).withSbom()).isEqualTo(1);
        assertThat(all.untargeted().scans()).isGreaterThanOrEqualTo(1);
        assertThat(all.untargeted().newestId()).isGreaterThanOrEqualTo(untargeted);
        assertThat(catalog.sbomsOfUntargeted()).extracting(ScanCatalog.ScanSbom::id).contains(untargeted)
                .doesNotContain(completed, imageScan);
        assertThat(catalog.sboms()).extracting(ScanCatalog.ScanSbom::id)
                .contains(completed, failed, pending, imageScan, untargeted);

        assertThat(catalog.withSbom()).extracting(ScanCatalog.ScanOfTarget::id)
                .contains(completed, failed, imageScan)
                .doesNotContain(pending);

        List<ScanTarget> asked = Stream.of(
                        NOBODY.stream().<ScanTarget>map(ScanTarget.Repository::new),
                        Stream.<ScanTarget>of(repository),
                        NOBODY.stream().<ScanTarget>map(ScanTarget.Container::new),
                        Stream.<ScanTarget>of(image))
                .flatMap(targets -> targets)
                .toList();
        assertThat(catalog.sbomsOfTargets(asked)).extracting(ScanCatalog.ScanSbom::id)
                .containsExactlyInAnyOrder(completed, failed, pending, imageScan);
        // The component names the inventory reads, as a projection, in scan and row order.
        assertThat(components.namesOfScans(List.of(completed)))
                .extracting(row -> row.name() + "@" + row.version())
                .containsExactly("a@1", "b@1");

        Visibility both = Visibility.only(List.of(repository, image));
        Map<ScanTarget, Long> expected = licences.getInventory(both, null, null).stream()
                .filter(entry -> !entry.compliant())
                .collect(Collectors.groupingBy(
                        entry -> "repository".equals(entry.targetKind())
                                ? new ScanTarget.Repository(entry.targetId())
                                : new ScanTarget.Container(entry.targetId()),
                        Collectors.counting()));
        // a (GPL, from the SBOM) and c (AGPL, a finding); b is an unknown licence the default allows.
        assertThat(expected).containsExactly(Map.entry(repository, 2L));
        assertThat(licences.violationsByTarget(both)).containsOnly(Map.entry(repository, 2L), Map.entry(image, 0L));
        assertThat(licences.violationsWithin(both)).isEqualTo(2);
        // The estate's inventory reads every scan, the one attached to no target among them.
        long refused = licences.getInventory(Visibility.everything(), null, null).stream()
                .filter(entry -> !entry.compliant()).count();
        assertThat(licences.violationsWithin(Visibility.everything())).isEqualTo(refused);
        assertThat(licences.getSummary(Visibility.everything(), null, null).nonCompliantCount()).isEqualTo(refused);
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/tally-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long container() {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("tally-" + System.nanoTime());
        container.setTag("latest");
        return containers.save(container).getId();
    }

    private long scan(Long repositoryId, Long containerId, ScanStatus status, String sbom) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setContainerId(containerId);
        scan.setBranch("main");
        scan.setStatus(status.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setAttempts(1);
        scan.setSbom(sbom);
        return scans.save(scan).getId();
    }

    private void component(long scanId, String name, String version) {
        ScanEntity scan = scans.findById(scanId).orElseThrow();
        ComponentEntity component = new ComponentEntity();
        component.setScanId(scanId);
        component.setRepoId(scan.getRepoId());
        component.setContainerId(scan.getContainerId());
        component.setScanCreatedAt(scan.getCreatedAt());
        component.setName(name);
        component.setVersion(version);
        component.setType("library");
        components.save(component);
    }

    private void licenceFinding(long scanId, String name, String version, String licence) {
        jdbc.update("insert into t_finding (scan_id, type, source, package_name, package_version, identifier, is_kev,"
                        + " created_at, reachability) values (?, 'license', 'trivy', ?, ?, ?, ?, ?, 'UNKNOWN')",
                scanId, name, version, licence, Boolean.FALSE, Timestamp.from(Instant.now()));
    }
}

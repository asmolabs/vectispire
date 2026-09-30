package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.inventory.ConsolidatedInventoryService.ConsolidatedInventory;
import com.asmolabs.vectispire.core.inventory.ConsolidatedInventoryService.InventoryState;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.scanning.persistence.queries.NewestCompletedScanRow;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import com.asmolabs.vectispire.core.targets.SolutionQueryService.ProjectDetail;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.LongStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * A project's scope and its consolidated inventory on a real engine (decision 0023).
 *
 * <p>Two things only a server can say. The newest completed scan of each target is a correlated {@code
 * max} with a {@code case} over a large-object column ({@code sbom is null}), which each engine reads its
 * own way. And the targets are sized by the data: one bind parameter each, so the catalogue asks a
 * thousand at a time, and this hands it seventy thousand repositories and seventy thousand images. That
 * limit is <b>PostgreSQL's alone</b> — the driver refuses a statement past 65,535 parameters; MySQL's
 * client-side statements and the SQLite driver accepted such a statement when measured — so a green run
 * on those two proves the queries, not the batching.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("a project's scope and consolidated inventory, on the engine")
class ProjectScopeIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    /** Seventy thousand identifiers no row carries — past the PostgreSQL driver's 65,535. */
    private static final List<Long> NOBODY = LongStream.rangeClosed(8_000_000, 8_070_000).boxed().toList();

    private static final VisibilityService.Allowance EVERYTHING = new VisibilityService.Allowance(Visibility.everything(), Set.of());

    @BeforeAll
    static void start() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::start);
    }

    @AfterAll
    static void stop() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::stop);
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private ScanCatalog catalog;

    @Autowired
    private ConsolidatedInventoryService inventory;

    @Autowired
    private SolutionQueryService solutionsQuery;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private ProjectRepository projects;

    @Autowired
    private SolutionRepository solutions;

    @Test
    @DisplayName("past the bind limit, each target's newest completed scan and whether it holds its SBOM, by its own column")
    void newestCompletedPastTheBindLimit() {
        long repository = repository();
        scan(repository, null, ScanStatus.COMPLETED, null);
        long newest = scan(repository, null, ScanStatus.COMPLETED, "{\"artifacts\":[]}");
        scan(repository, null, ScanStatus.FAILED, "{\"artifacts\":[]}");
        scan(repository, null, ScanStatus.PENDING, null);
        long image = container();
        long imageScan = scan(null, image, ScanStatus.COMPLETED, null);
        long failedOnly = repository();
        scan(failedOnly, null, ScanStatus.FAILED, null);
        // A repository whose number is asked as an image's: read against the wrong column it would answer.
        long namedAsImage = repository();
        scan(namedAsImage, null, ScanStatus.COMPLETED, null);
        assertThat(namedAsImage).as("the probe needs a number no scanned image carries").isNotEqualTo(image);

        List<ScanTarget> asked = Stream.of(
                        NOBODY.stream().<ScanTarget>map(ScanTarget.Repository::new),
                        Stream.<ScanTarget>of(new ScanTarget.Repository(repository), new ScanTarget.Repository(failedOnly)),
                        NOBODY.stream().<ScanTarget>map(ScanTarget.Container::new),
                        Stream.<ScanTarget>of(new ScanTarget.Container(image), new ScanTarget.Container(namedAsImage)))
                .flatMap(targets -> targets)
                .toList();

        Map<ScanTarget, NewestCompletedScanRow> found = catalog.newestCompleted(asked);

        assertThat(found).containsOnlyKeys(new ScanTarget.Repository(repository), new ScanTarget.Container(image));
        NewestCompletedScanRow ofRepository = found.get(new ScanTarget.Repository(repository));
        assertThat(ofRepository.scanId()).as("the newest completed, not the newer failed or pending").isEqualTo(newest);
        assertThat(ofRepository.sbomStored()).isTrue();
        assertThat(ofRepository.createdAt()).isNotNull();
        NewestCompletedScanRow ofImage = found.get(new ScanTarget.Container(image));
        assertThat(ofImage.scanId()).isEqualTo(imageScan);
        assertThat(ofImage.sbomStored()).isFalse();
        assertThat(catalog.newestCompleted(List.of())).isEmpty();
    }

    @Test
    @DisplayName("a project read, its scope and its merged inventory, through the new lookups")
    void aProjectOnTheEngine() {
        long solution = solution();
        long project = project(solution);
        long api = repository();
        long web = repository();
        long image = container();
        repositories.assignProject(api, project);
        repositories.assignProject(web, project);
        containers.assignProject(image, project);
        long unfiled = repository();
        component(scan(unfiled, null, ScanStatus.COMPLETED, "{}"), "unfiled-lib", "1", "pkg:npm/unfiled-lib@1");

        component(scan(api, null, ScanStatus.COMPLETED, "{}"), "shared", "1.0", "pkg:npm/shared@1.0");
        long webScan = scan(web, null, ScanStatus.COMPLETED, "{}");
        component(webScan, "shared", "1.0", "pkg:npm/shared@1.0");
        component(webScan, "only-web", "2.0", null);

        ProjectDetail read = solutionsQuery.project(project, EVERYTHING);
        assertThat(read.repositories()).extracting(SolutionQueryService.RepositoryRef::id).containsExactlyInAnyOrder(api, web);
        assertThat(read.containers()).extracting(SolutionQueryService.ContainerRef::id).containsExactly(image);
        assertThat(read.solution().id()).isEqualTo(solution);

        VisibleScope scope = solutionsQuery.visibleProject(project, EVERYTHING);
        assertThat(scope.targets()).containsExactly(
                new ScanTarget.Repository(Math.min(api, web)),
                new ScanTarget.Repository(Math.max(api, web)),
                new ScanTarget.Container(image));
        assertThat(solutionsQuery.visibleSolution(solution, EVERYTHING).targets()).isEqualTo(scope.targets());

        ConsolidatedInventory merged = inventory.of(scope);
        assertThat(merged.complete()).as("the image was never scanned").isFalse();
        assertThat(merged.targets()).extracting(ConsolidatedInventoryService.TargetInventory::inventory)
                .containsExactly(InventoryState.LISTED, InventoryState.LISTED, InventoryState.NEVER_SCANNED);
        assertThat(merged.components()).extracting(ConsolidatedInventoryService.MergedComponent::name)
                .containsExactly("only-web", "shared");
        assertThat(merged.components().get(1).targets()).hasSize(2);
    }

    private long solution() {
        SolutionEntity solution = new SolutionEntity();
        solution.setName("scope-" + System.nanoTime());
        solution.setCreatedAt(Instant.now());
        return solutions.save(solution).getId();
    }

    private long project(long solution) {
        ProjectEntity project = new ProjectEntity();
        project.setSolutionId(solution);
        project.setName("scope-" + System.nanoTime());
        project.setCreatedAt(Instant.now());
        return projects.save(project).getId();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/scope-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long container() {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("scope-" + System.nanoTime());
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

    private void component(long scanId, String name, String version, String purl) {
        ComponentEntity component = new ComponentEntity();
        component.setScanId(scanId);
        // The scan's target and instant, as ComponentInventory copies them (V61).
        ScanEntity scanOfComponent = scans.findById(scanId).orElseThrow();
        component.setRepoId(scanOfComponent.getRepoId());
        component.setContainerId(scanOfComponent.getContainerId());
        component.setScanCreatedAt(scanOfComponent.getCreatedAt());
        component.setName(name);
        component.setVersion(version);
        component.setPurl(purl);
        component.setType("library");
        components.save(component);
    }
}

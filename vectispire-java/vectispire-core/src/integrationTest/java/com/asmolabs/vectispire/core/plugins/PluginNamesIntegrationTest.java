package com.asmolabs.vectispire.core.plugins;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.access.ApiKeyAdministrationService;
import com.asmolabs.vectispire.core.access.persistence.ApiKeyEntity;
import com.asmolabs.vectispire.core.access.persistence.ApiKeyRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService.ProjectLabel;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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
 * The names the plugin lists carry — an activation's project and solution, a declared source's key —
 * looked up for seventy thousand identifiers on a real engine: the rows are sized by the data.
 *
 * <p>PostgreSQL is the engine that refuses an unbatched statement here ("at most 65 535 parameters");
 *  * MySQL's client-side statements accept one, so a green run on MySQL alone says nothing of the batching.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the plugin lists' names on the engine")
class PluginNamesIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    /** Seventy thousand identifiers no row carries — past the PostgreSQL driver's 65,535. */
    private static final List<Long> NOBODY = LongStream.rangeClosed(5_000_000, 5_070_000).boxed().toList();

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
    private SolutionAdministrationService solutionAdministration;

    @Autowired
    private ApiKeyAdministrationService apiKeyAdministration;

    @Autowired
    private SolutionRepository solutions;

    @Autowired
    private ProjectRepository projects;

    @Autowired
    private ApiKeyRepository keys;

    @Test
    @DisplayName("an activation's project and solution, among seventy thousand identifiers")
    void projectLabels() {
        SolutionEntity solution = new SolutionEntity();
        solution.setName("Payments " + System.nanoTime());
        solution.setCreatedAt(Instant.now());
        long solutionId = solutions.save(solution).getId();
        long checkout = project(solutionId, "checkout");
        long ledger = project(solutionId, "ledger");

        List<Long> ids = new ArrayList<>();
        ids.add(checkout);
        ids.addAll(NOBODY);
        ids.add(ledger);
        Map<Long, ProjectLabel> labels = solutionAdministration.projectLabels(ids);

        assertThat(labels).containsOnlyKeys(checkout, ledger);
        assertThat(labels.get(ledger)).isEqualTo(new ProjectLabel(ledger, "ledger", solutionId, solution.getName()));
    }

    @Test
    @DisplayName("a declared source's key name, among seventy thousand identifiers")
    void keyNames() {
        UUID first = key("team-ci");
        UUID last = key("release-ci");

        List<UUID> ids = Stream.concat(
                        Stream.of(first),
                        Stream.concat(NOBODY.stream().map(n -> new UUID(0L, n)), Stream.of(last)))
                .toList();
        Map<UUID, String> names = apiKeyAdministration.names(ids);

        assertThat(names).containsOnlyKeys(first, last);
        assertThat(names.get(last)).isEqualTo("release-ci");
    }

    private long project(long solutionId, String name) {
        ProjectEntity project = new ProjectEntity();
        project.setSolutionId(solutionId);
        project.setName(name);
        project.setCreatedAt(Instant.now());
        return projects.save(project).getId();
    }

    private UUID key(String name) {
        ApiKeyEntity key = new ApiKeyEntity();
        key.setName(name);
        key.setKeyHash("not a real hash");
        key.setScopes("sarif_import");
        key.setCreatedAt(Instant.now());
        return keys.save(key).getId();
    }
}

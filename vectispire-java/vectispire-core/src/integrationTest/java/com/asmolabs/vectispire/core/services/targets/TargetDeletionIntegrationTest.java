package com.asmolabs.vectispire.core.services.targets;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * Deleting a target on a real engine, with the foreign keys the migrations declare.
 *
 * <p><b>What this adds to the unit suite.</b> {@code TargetDeletionTest} runs on SQLite, whose keys
 * hold only because the pool issues a pragma; here they are MySQL's and PostgreSQL's own, declared by
 * V19 and the migrations after it. A purge that deleted a parent before a child the schema does not
 * cascade, or left a row the schema would refuse to orphan, fails here on the engine that refuses it
 * — which is where an operator would otherwise have found it.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("deleting a target on a real engine")
class TargetDeletionIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

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
    private TargetDeletionService deletion;

    @Autowired
    private BeanFactory beans;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("a repository takes its rows in every dependent table, and nobody else's")
    void repository() {
        TargetRowsFixture fixture = new TargetRowsFixture(beans, jdbc);
        ScanTarget doomed = fixture.repository("doomed-" + ENGINE);
        ScanTarget survivor = fixture.repository("survivor-" + ENGINE);
        fixture.populate(doomed);
        fixture.populate(survivor);
        Map<String, Integer> before = fixture.rowsNaming(survivor);
        assertThat(fixture.rowsNaming(doomed).values()).as("the fixture wrote a row everywhere").doesNotContain(0);

        long repoId = ((ScanTarget.Repository) doomed).id();
        deletion.deleteRepository(repoId);

        assertThat(fixture.rowsNaming(doomed)).as("nothing naming the deleted repository remains on %s", ENGINE)
                .allSatisfy((table, rows) -> assertThat(rows).as(table).isZero());
        assertThat(fixture.rowsNaming(survivor)).as("the other repository keeps every row").isEqualTo(before);
        assertThat(jdbc.queryForObject("select count(*) from t_repository where id = ?", Integer.class, repoId))
                .isZero();
    }

    @Test
    @DisplayName("a container image takes its rows the same way")
    void container() {
        TargetRowsFixture fixture = new TargetRowsFixture(beans, jdbc);
        ScanTarget doomed = fixture.container("doomed-" + ENGINE);
        ScanTarget survivor = fixture.container("survivor-" + ENGINE);
        fixture.populate(doomed);
        fixture.populate(survivor);
        Map<String, Integer> before = fixture.rowsNaming(survivor);

        long containerId = ((ScanTarget.Container) doomed).id();
        deletion.deleteContainer(containerId);

        assertThat(fixture.rowsNaming(doomed)).allSatisfy((table, rows) -> assertThat(rows).as(table).isZero());
        assertThat(fixture.rowsNaming(survivor)).isEqualTo(before);
        assertThat(jdbc.queryForObject("select count(*) from t_container where id = ?", Integer.class, containerId))
                .isZero();
    }
}

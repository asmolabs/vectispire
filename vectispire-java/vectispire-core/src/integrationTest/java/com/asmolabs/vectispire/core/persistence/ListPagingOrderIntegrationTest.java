package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPathGraph;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.access.ScimProvisioningService;
import com.asmolabs.vectispire.core.access.persistence.TeamEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamRepository;
import com.asmolabs.vectispire.core.issues.HistoryQueryService;
import com.asmolabs.vectispire.core.issues.TriageHistory;
import com.asmolabs.vectispire.core.posture.AttackPathService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
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
 * The lists that page on request are ordered by a key, not by where the engine keeps their rows.
 *
 * <p><b>The case is PostgreSQL's.</b> It writes an updated row as a new tuple after its neighbours, and a scan
 * of the table returns it there: the first repository filed, renamed, comes back last. MySQL reads a table in
 * its primary key's order whatever was updated, so the HTTP suite, which runs on MySQL, cannot tell an order
 * by identifier from the table's — the lists sorted nothing and passed there. On MySQL this checks the same
 * answers, which the table's order happens to give.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the pageable lists' orders, on the engine")
class ListPagingOrderIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

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
    private AttackPathService attackPaths;

    @Autowired
    private HistoryQueryService history;

    @Autowired
    private ScimProvisioningService scim;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private TeamRepository teams;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    @DisplayName("a repository updated after its neighbours keeps its place in the overview and the triage history")
    void anUpdatedRepositoryKeepsItsPlace() {
        List<Long> filed = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            filed.add(repository("ordered-" + i));
        }
        jdbc.update("update t_repository set branch = 'develop' where id = ?", filed.getFirst());
        if (ENGINE == Engine.POSTGRES) {
            // The premise, or this case checks nothing: the table now hands the first repository back last.
            assertThat(mine(jdbc.queryForList("select id from t_repository", Long.class), filed, id -> id))
                    .containsExactly(filed.get(1), filed.get(2), filed.getFirst());
        }

        Visibility everything = Visibility.everything();
        assertThat(mine(attackPaths.getOverview(everything), filed, AttackPathGraph::targetId))
                .containsExactlyElementsOf(filed);
        assertThat(mine(attackPaths.getOverview(everything, 500, 0), filed, AttackPathGraph::targetId))
                .containsExactlyElementsOf(filed);
        // Never scanned, all three: the instant ties, and the identifier settles it.
        assertThat(mine(history.repositories(everything, null, null), filed, TriageHistory.Repository::id))
                .containsExactlyElementsOf(filed);
    }

    @Test
    @DisplayName("a team updated after its neighbours keeps its place in SCIM's groups")
    void anUpdatedTeamKeepsItsPlace() {
        List<Long> filed = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            filed.add(team("ordered-" + i + "-" + System.nanoTime()));
        }
        jdbc.update("update t_team set description = 'renamed' where id = ?", filed.getFirst());
        if (ENGINE == Engine.POSTGRES) {
            assertThat(mine(jdbc.queryForList("select id from t_team", Long.class), filed, id -> id))
                    .containsExactly(filed.get(1), filed.get(2), filed.getFirst());
        }

        assertThat(mine(scim.groups(null, null).resources(), filed, ScimProvisioningService.GroupView::id))
                .containsExactlyElementsOf(filed);
    }

    private static <T> List<Long> mine(List<T> rows, List<Long> filed, Function<T, Long> idOf) {
        return rows.stream().map(idOf).filter(filed::contains).toList();
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setName(name);
        repository.setUrl("https://example.invalid/" + name + "-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long team(String name) {
        TeamEntity team = new TeamEntity();
        team.setName(name);
        team.setCreatedAt(Instant.parse("2026-10-01T00:00:00Z"));
        return teams.save(team).getId();
    }
}

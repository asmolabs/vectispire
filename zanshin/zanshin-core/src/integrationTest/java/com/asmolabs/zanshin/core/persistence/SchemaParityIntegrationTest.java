package com.asmolabs.zanshin.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.core.ZanshinApplication;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The question whose right answer is "nothing".
 *
 * <p>Liquibase builds the schema, then Hibernate is asked to <b>validate</b> the entities
 * against it. Every disagreement — a column the entities expect and the changelog never
 * creates, a length that differs, a nullability that does not — fails the context startup here
 * rather than on the first query in production.
 *
 * <p><b>There is no "skip if Docker is missing" guard, deliberately.</b> A suite that skips
 * itself reports green without having checked anything, which is worse than one that fails.
 *
 * <p>Run one engine with {@code -Pdialect=mariadb}, or all four with {@code integrationTestAll}.
 * Running one is not running the campaign: the places the engines disagree are precisely the
 * places a single representative is silent about — MySQL reports {@code tinyint(1)} where
 * MariaDB reports {@code tinyint}, and they disagree with <em>each other</em>.
 */
@SpringBootTest(classes = ZanshinApplication.class)
@DisplayName("the entities agree with the schema")
class SchemaParityIntegrationTest {

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
        CONTAINER.ifPresentOrElse(
                container -> {
                    registry.add("spring.datasource.url", container::getJdbcUrl);
                    registry.add("spring.datasource.username", container::getUsername);
                    registry.add("spring.datasource.password", container::getPassword);
                    registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
                },
                () -> {
                    registry.add("spring.datasource.url", () -> "jdbc:sqlite:" + Engine.sqliteFile());
                    registry.add("spring.datasource.username", () -> "");
                    registry.add("spring.datasource.password", () -> "");
                    registry.add("spring.jpa.database-platform",
                            () -> "org.hibernate.community.dialect.SQLiteDialect");
                    // Not `validate` here, and the reason is in `Engine`: SQLite has affinities
                    // rather than types, so the comparison would be about naming. The round trip
                    // below is what proves the mapping on this engine.
                    registry.add("spring.jpa.hibernate.ddl-auto", () -> "none");
                });
    }

    @Autowired
    private EntityManager entityManager;

    @Test
    @DisplayName("every entity is mapped, and on a typed engine validated against the schema")
    void entitiesMatchTheSchema() {
        // On the three typed engines, reaching this line *is* the assertion: Hibernate validated
        // all nineteen while the context came up. The count below stops the test from passing on
        // an empty metamodel, which is how an architecture check reports green having looked at
        // nothing.
        assertThat(entityManager.getMetamodel().getEntities()).hasSize(19);
    }

    @Test
    @Transactional
    @DisplayName("a row survives the round trip, types included")
    void rowRoundTrips() {
        // What strict validation cannot say, on any engine: that the values come back as they
        // went in. The three columns below are the ones the engines disagree about — an
        // instant, a boolean, and a UUID stored as text.
        AgentEntity agent = new AgentEntity();
        agent.setName("campaign");
        agent.setKind("remote");
        agent.setCredentialsMode("sealed");
        agent.setEnabled(true);
        agent.setCreatedAt(Instant.parse("2026-08-13T10:00:00Z").truncatedTo(ChronoUnit.MILLIS));
        agent.setCapabilities("{\"docker\":true}");

        entityManager.persist(agent);
        entityManager.flush();
        entityManager.clear();

        UUID id = agent.getId();
        assertThat(id).as("the identifier must be generated, whatever the engine calls a UUID").isNotNull();

        AgentEntity reloaded = entityManager.find(AgentEntity.class, id);
        assertThat(reloaded.getName()).isEqualTo("campaign");
        // A boolean is `boolean` on two engines, `tinyint(1)` on one and `tinyint` on another.
        // Reading it back as `true` is the only claim that means the same thing on all four.
        assertThat(reloaded.getEnabled()).isTrue();
        // Truncated to the millisecond going in, so this compares the value and not the
        // engine's fractional-second precision.
        assertThat(reloaded.getCreatedAt()).isEqualTo(Instant.parse("2026-08-13T10:00:00Z"));
        assertThat(reloaded.getCapabilities()).isEqualTo("{\"docker\":true}");
    }
}

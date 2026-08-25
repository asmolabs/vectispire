package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireApplication;
import jakarta.persistence.EntityManager;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
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
 * <p>Flyway builds the schema from the per-dialect migrations, then Hibernate is asked to
 * <b>validate</b> the entities against it. Every disagreement — a column the entities expect and
 * the migrations never create, a length that differs, a nullability that does not — fails the
 * context startup here rather than on the first query in production.
 *
 * <p><b>There is no "skip if Docker is missing" guard, deliberately.</b> A suite that skips
 * itself reports green without having checked anything, which is worse than one that fails.
 *
 * <p>Run one engine with {@code -Pdialect=postgres}, or the whole set with {@code integrationTestAll}.
 * Running one is not running the campaign: the places the engines disagree are precisely the
 * places a single representative is silent about — MySQL reports a boolean as {@code tinyint(1)}
 * where PostgreSQL has a real one, and a timestamp without declared precision truncates on one
 * and not the other.
 */
@SpringBootTest(classes = VectispireApplication.class)
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

    @Autowired
    private DataSource dataSource;

    @Test
    @DisplayName("every entity is mapped, and on a typed engine validated against the schema")
    void entitiesMatchTheSchema() {
        // On the three typed engines, reaching this line *is* the assertion: Hibernate validated
        // every entity while the context came up. What remains is to stop the test passing on an
        // empty metamodel, which is how a check reports green having looked at nothing.
        //
        // **A lower bound, not an exact count, and that is a correction.** This asserted exactly
        // 26 and the tree now has 33: ticketing, the API inventory, threat intel and the SIEM
        // configuration each added one, and none of them touched this line. So the whole
        // four-engine campaign failed — on a number, not on a mapping — and nobody saw it,
        // because the campaign does not run in CI. An exact count here checks that somebody
        // updated a literal; it does not check the schema, and it is the failure mode this file
        // exists to avoid.
        assertThat(entityManager.getMetamodel().getEntities())
                .as("an empty or near-empty metamodel means the scan found nothing, not that the "
                        + "schema is fine")
                .hasSizeGreaterThanOrEqualTo(26);
    }

    @Test
    @DisplayName("the columns the hot paths filter on are indexed, on every engine")
    void theHotLookupsAreIndexed() throws Exception {
        // **An index nobody checks is an index a refactor drops.** This table carried none at all
        // for the whole life of the project while a published document claimed three, so the
        // assertion is that they exist rather than that somebody remembered to write them.
        //
        // Read through `DatabaseMetaData` rather than a catalog query: `pg_indexes`,
        // `information_schema.statistics` and `pragma index_list` are three different questions,
        // and the campaign exists to ask one question of three engines.
        Set<String> indexedFirstColumns = new HashSet<>();
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metadata = connection.getMetaData();
            for (String table : new String[] {"t_issue", "T_ISSUE"}) {
                try (ResultSet indexes = metadata.getIndexInfo(
                        connection.getCatalog(), null, table, false, false)) {
                    while (indexes.next()) {
                        String column = indexes.getString("COLUMN_NAME");
                        if (column != null && indexes.getShort("ORDINAL_POSITION") == 1) {
                            indexedFirstColumns.add(column.toLowerCase(Locale.ROOT));
                        }
                    }
                }
            }
        }

        assertThat(indexedFirstColumns)
                .as("the gate reads one target's open issues on every build, and the compliance "
                        + "summary groups the open backlog — both lead with `state`")
                .contains("state");
        assertThat(indexedFirstColumns)
                .as("the fingerprint is looked up once per ingested finding: a scan producing two "
                        + "thousand findings would otherwise scan this table two thousand times")
                .contains("fingerprint");
    }

    @Test
    @DisplayName("a fingerprint appears once, and the engine says so rather than the code hoping so")
    void theFingerprintIsUnique() throws Exception {
        // **The identity an issue has always had, now enforced by the schema.** Reconciliation
        // collects existing rows with a merge function that only fires on a duplicate, so the
        // code has been tolerating what this constraint forbids; two overlapping scans of one
        // target could each look up a fingerprint, each find nothing, and each insert.
        //
        // Read through `DatabaseMetaData` because `pg_indexes`, `information_schema.statistics`
        // and `pragma index_list` are three different questions and the campaign asks one.
        //
        // **`NON_UNIQUE` is read rather than trusting the `unique` argument, and that is not
        // belt-and-braces.** The first version of this test passed `unique = true` and passed
        // with no unique index at all: the SQLite driver ignores the flag and returns every
        // index regardless. Found by running it against the engine with the constraint removed —
        // an assertion that cannot fail is the failure mode this campaign exists to catch, and
        // it caught one of its own.
        boolean unique = false;
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metadata = connection.getMetaData();
            for (String table : new String[] {"t_issue", "T_ISSUE"}) {
                try (ResultSet indexes = metadata.getIndexInfo(
                        connection.getCatalog(), null, table, false, false)) {
                    while (indexes.next()) {
                        String column = indexes.getString("COLUMN_NAME");
                        if (column != null
                                && "fingerprint".equalsIgnoreCase(column)
                                && !indexes.getBoolean("NON_UNIQUE")) {
                            unique = true;
                        }
                    }
                }
            }
        }

        assertThat(unique)
                .as("the fingerprint must be unique on every engine: an issue that exists twice "
                        + "is counted twice everywhere and refreshed in only one of its copies")
                .isTrue();
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

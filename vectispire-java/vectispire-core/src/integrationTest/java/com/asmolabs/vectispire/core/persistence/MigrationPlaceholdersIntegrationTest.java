package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireApplication;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import javax.sql.DataSource;
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
 * What a common migration's placeholders become, measured on each engine (decision 0027).
 *
 * <p>The probe, {@code V9000__placeholder_probe.sql}, is a common migration using every
 * placeholder. It is applied <b>through the application's own Flyway</b> — the locations of
 * {@code application.yaml} plus the probe's, and {@code MigrationPlaceholders} as the only source
 * of values — so a customizer that is not registered fails here as an unresolved {@code ${id}},
 * which is the one way to prove it is wired.
 *
 * <p>Two kinds of assertion, because each misses what the other sees. The declared types are read
 * from each engine's catalog: that is where {@code datetime} and {@code datetime(6)} differ, which
 * decision 0013 is about. The behaviour is then written and read back: that is where an
 * {@code integer primary key} without {@code autoincrement} would reuse a deleted id on SQLite
 * while declaring nothing a catalog shows as wrong.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the migration placeholders, on a real engine")
class MigrationPlaceholdersIntegrationTest {

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
        registry.add("spring.flyway.locations", () -> "classpath:db/migration/common,"
                + "classpath:db/migration/{vendor},classpath:db/migration-test/common");
    }

    @Autowired
    private DataSource dataSource;

    @Test
    @DisplayName("each placeholder declares the type MigrationDialect promises")
    void theDeclaredTypes() throws Exception {
        Map<String, String> declared = declaredTypes();

        switch (ENGINE) {
            case MYSQL -> assertThat(declared)
                    .containsEntry("id", "bigint auto_increment pri")
                    // The reason decision 0013 exists: `datetime` alone truncates to the second.
                    .containsEntry("observed_at", "datetime(6)")
                    .containsEntry("unset_flag", "bit(1)")
                    .containsEntry("set_flag", "bit(1)")
                    .containsEntry("body", "longtext")
                    .containsEntry("score", "double");
            case POSTGRES -> assertThat(declared)
                    .containsEntry("id", "bigint identity always")
                    .containsEntry("observed_at", "timestamp with time zone")
                    .containsEntry("unset_flag", "boolean")
                    .containsEntry("set_flag", "boolean")
                    .containsEntry("body", "text")
                    .containsEntry("score", "double precision");
            case SQLITE -> assertThat(declared)
                    // Only this exact spelling aliases the rowid; `autoincrement` is proven below.
                    .containsEntry("id", "integer pk")
                    .containsEntry("observed_at", "numeric")
                    .containsEntry("unset_flag", "boolean")
                    .containsEntry("set_flag", "boolean")
                    .containsEntry("body", "text")
                    .containsEntry("score", "double");
        }
    }

    @Test
    @DisplayName("an identity is generated, increases, and never reuses a deleted row's id")
    void theIdentity() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            long first = insert(connection, "first");
            long second = insert(connection, "second");
            try (Statement statement = connection.createStatement()) {
                statement.executeUpdate("delete from t_placeholder_probe where id = " + second);
            }
            long third = insert(connection, "third");

            assertThat(second).isGreaterThan(first);
            assertThat(third)
                    .as("an id handed out once must not come back: SQLite's `integer primary key` "
                            + "without `autoincrement` gives the deleted last row's id to the next")
                    .isGreaterThan(second);

            if (ENGINE == Engine.SQLITE) {
                try (Statement statement = connection.createStatement();
                        ResultSet rows = statement.executeQuery(
                                "select count(*) from sqlite_sequence where name = 't_placeholder_probe'")) {
                    rows.next();
                    assertThat(rows.getInt(1)).as("autoincrement keeps its counter here").isEqualTo(1);
                }
            }
        }
    }

    @Test
    @DisplayName("the values survive the round trip: millisecond, booleans, long text, double")
    void theValues() throws Exception {
        Instant observed = Instant.parse("2026-09-26T10:15:30.123Z");
        String body = "x".repeat(70_000);
        try (Connection connection = dataSource.getConnection()) {
            try (PreparedStatement insert = connection.prepareStatement(
                    "insert into t_placeholder_probe (label, observed_at, body, score) values (?, ?, ?, ?)")) {
                insert.setString(1, "values");
                insert.setTimestamp(2, Timestamp.from(observed));
                insert.setString(3, body);
                insert.setDouble(4, 0.1);
                insert.executeUpdate();
            }
            try (Statement statement = connection.createStatement();
                    ResultSet row = statement.executeQuery("select observed_at, unset_flag, set_flag, body, score"
                            + " from t_placeholder_probe where label = 'values'")) {
                assertThat(row.next()).isTrue();
                assertThat(row.getTimestamp("observed_at").toInstant())
                        .as("the audit chain hashes the millisecond; a column that drops it breaks the chain")
                        .isEqualTo(observed);
                assertThat(row.getBoolean("unset_flag")).as("${false} as a default").isFalse();
                assertThat(row.getBoolean("set_flag")).as("${true} as a default").isTrue();
                assertThat(row.getString("body"))
                        .as("past MySQL's 64 KiB `text`, which is why ${text} is `longtext` there")
                        .hasSize(body.length());
                assertThat(row.getDouble("score")).as("a float would not give 0.1 back").isEqualTo(0.1);
            }
        }
    }

    private static long insert(Connection connection, String label) throws Exception {
        try (PreparedStatement insert = connection.prepareStatement(
                "insert into t_placeholder_probe (label, observed_at) values (?, ?)",
                Statement.RETURN_GENERATED_KEYS)) {
            insert.setString(1, label);
            insert.setTimestamp(2, Timestamp.from(Instant.parse("2026-09-26T00:00:00Z")));
            insert.executeUpdate();
            try (ResultSet keys = insert.getGeneratedKeys()) {
                assertThat(keys.next()).as("the engine generated the id").isTrue();
                return keys.getLong(1);
            }
        }
    }

    /**
     * Column name to its declared type, lowercased, with the identity facts each catalog reports
     * appended — three catalogs, because the question ({@code datetime(6)} or not) is only
     * answered by the engine's own vocabulary; {@code DatabaseMetaData} reports both as TIMESTAMP.
     */
    private Map<String, String> declaredTypes() throws Exception {
        String query = switch (ENGINE) {
            case MYSQL -> "select column_name, concat_ws(' ', column_type,"
                    + " nullif(extra, ''), nullif(lower(column_key), ''))"
                    + " from information_schema.columns"
                    + " where table_schema = database() and table_name = 't_placeholder_probe'";
            case POSTGRES -> "select column_name, concat_ws(' ', data_type,"
                    + " case when is_identity = 'YES' then 'identity' end, lower(identity_generation))"
                    + " from information_schema.columns where table_name = 't_placeholder_probe'";
            case SQLITE -> "select name, lower(type) || case when pk = 1 then ' pk' else '' end"
                    + " from pragma_table_info('t_placeholder_probe')";
        };
        Map<String, String> types = new TreeMap<>();
        List<String> seen = new ArrayList<>();
        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery(query)) {
            while (rows.next()) {
                String column = rows.getString(1).toLowerCase(Locale.ROOT);
                seen.add(column);
                types.put(column, rows.getString(2).toLowerCase(Locale.ROOT).trim());
            }
        }
        assertThat(seen).as("the probe table exists and was read").hasSize(7);
        return types;
    }
}

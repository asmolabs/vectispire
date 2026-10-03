package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.config.MigrationDialect;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Optional;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * V69 writes the day an installation's grades changed formula (decision 0036), on the engine — the
 * dashboard's trend chart draws its dated line there.
 *
 * <p>Written twice, once per engine, because the two spell "today as an ISO date" differently: a
 * format string wrong on one of them would write a value the chart refuses (no line at all) or a wrong
 * day, and only on the installations of that engine. And only where there were grades to change — an
 * installation holding a completed scan at the upgrade — so a fresh one draws no line for a change
 * nobody saw. Neither is visible on the fresh databases every other suite starts from: the migration
 * runs there with no scan at all. So this builds the schema up to V68, writes the scans an installation
 * held then, applies the rest, and reads the row.
 *
 * <p>Flyway alone, with the application's locations and placeholders for the engine, as
 * {@code ScanFactCopiesIntegrationTest} does; the database is cleaned between the two estates.
 */
@DisplayName("the day the score formula changed, written at the upgrade")
class ScoreFormulaChangedOnIntegrationTest {

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

    @Test
    @DisplayName("an installation holding a completed scan records today's date, UTC; one holding none records nothing")
    void writtenWhereThereWereGrades() throws Exception {
        flyway(null).clean();
        flyway("68").migrate();
        try (Connection connection = connect()) {
            // A scan that never completed graded nothing: every target read no data.
            scan(connection, "failed");
        }
        flyway(null).migrate();
        try (Connection connection = connect()) {
            assertThat(changedOn(connection)).as("no completed scan, no line").isEmpty();
        }

        flyway(null).clean();
        flyway("68").migrate();
        try (Connection connection = connect()) {
            scan(connection, "completed");
        }
        LocalDate before = LocalDate.now(ZoneOffset.UTC);
        flyway(null).migrate();
        LocalDate after = LocalDate.now(ZoneOffset.UTC);
        try (Connection connection = connect()) {
            // Parsed as the route parses it: a value it refuses would draw no line.
            LocalDate written = LocalDate.parse(changedOn(connection).orElseThrow());
            assertThat(written).isBetween(before, after);
        }
    }

    private static Optional<String> changedOn(Connection connection) throws SQLException {
        String key = ENGINE == Engine.MYSQL ? "`key`" : "\"key\"";
        try (PreparedStatement statement = connection.prepareStatement(
                        "select value from t_setting where " + key + " = 'internal.scorecard_formula_changed_on'");
                ResultSet rows = statement.executeQuery()) {
            return rows.next() ? Optional.of(rows.getString(1)) : Optional.empty();
        }
    }

    private static void scan(Connection connection, String status) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "insert into t_scan (branch, status, created_at) values ('main', ?, ?)")) {
            statement.setString(1, status);
            statement.setTimestamp(2, Timestamp.from(Instant.now()));
            statement.executeUpdate();
        }
    }

    private static Flyway flyway(String target) {
        MigrationDialect dialect = switch (ENGINE) {
            case POSTGRES -> MigrationDialect.POSTGRESQL;
            case MYSQL -> MigrationDialect.MYSQL;
        };
        var configuration = Flyway.configure()
                .locations(dialect.locations().toArray(String[]::new))
                .placeholders(dialect.placeholders())
                .cleanDisabled(false);
        configuration.dataSource(CONTAINER.getJdbcUrl(), CONTAINER.getUsername(), CONTAINER.getPassword());
        if (target != null) {
            configuration.target(target);
        }
        return configuration.load();
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(CONTAINER.getJdbcUrl(), CONTAINER.getUsername(), CONTAINER.getPassword());
    }
}

package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.config.MigrationDialect;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * V61 and V62 fill the copies of their scans' facts on the rows already stored, on the engine.
 *
 * <p>The inventory's and the model review's reads stopped joining {@code t_scan} the day their rows
 * began carrying their scan's target and creation instant. A row written before that has only what
 * the migration's update gave it, so a copy left null there is a component missing from every search,
 * a target counted as having no inventory, a report the screen no longer finds — each silent, on an
 * installation that upgraded, and on none of the fresh databases every other suite starts from. So
 * this builds the schema up to V60, writes rows as the application did then, applies the rest, and
 * reads the copies back against the scans they came from.
 *
 * <p>Flyway alone, with the application's locations and placeholders for the engine
 * ({@link MigrationDialect}): a Spring context would validate the entities against a schema that does
 * not have their columns yet.
 */
@DisplayName("the copies of a scan's facts, filled on the rows stored before them")
class ScanFactCopiesIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    /** Microseconds, which MySQL's {@code datetime(6)} keeps and a bare {@code datetime} would not. */
    private static final Instant SCANNED = Instant.parse("2026-09-01T10:00:00.123456Z");

    @BeforeAll
    static void start() {
        CONTAINER.start();
    }

    @AfterAll
    static void stop() {
        CONTAINER.stop();
    }

    @Test
    @DisplayName("a component carries its scan's target and instant, a review its scan's repository")
    void theCopiesAreFilled() throws Exception {
        migrate("60");

        long repository;
        long image;
        long repositoryScan;
        long imageScan;
        try (Connection connection = connect()) {
            repository = insert(connection, "insert into t_repository (url, branch) values ('ssh://git@example.invalid/a.git', 'main')",
                    "t_repository");
            image = insert(connection, "insert into t_container (image_name, tag) values ('registry.invalid/app', '1.0')",
                    "t_container");
            repositoryScan = scan(connection, "repo_id", repository);
            imageScan = scan(connection, "container_id", image);
            component(connection, repositoryScan, "log4j-core");
            component(connection, imageScan, "openssl");
            try (PreparedStatement statement = connection.prepareStatement("insert into t_ai_review_result "
                    + "(scan_id, model, prompt, status, created_at) values (?, 'model', 'prompt', 'completed', ?)")) {
                statement.setLong(1, repositoryScan);
                statement.setTimestamp(2, Timestamp.from(SCANNED));
                statement.executeUpdate();
            }
        }

        migrate(null);

        try (Connection connection = connect()) {
            assertThat(copied(connection, repositoryScan)).as("the repository scan's component")
                    .isEqualTo(new Copied(repository, null, createdAt(connection, repositoryScan)));
            assertThat(copied(connection, imageScan)).as("the image scan's component")
                    .isEqualTo(new Copied(null, image, createdAt(connection, imageScan)));
            // The engines keep the microseconds, and the copy must too, or the search's order would
            // tie scans apart.
            assertThat(createdAt(connection, repositoryScan)).isEqualTo(SCANNED);
            try (Statement statement = connection.createStatement();
                    ResultSet rows = statement.executeQuery("select scan_id, repo_id from t_ai_review_result")) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getLong("scan_id")).isEqualTo(repositoryScan);
                assertThat(rows.getLong("repo_id")).as("the review's repository").isEqualTo(repository);
                assertThat(rows.next()).isFalse();
            }
        }
    }

    private record Copied(Long repoId, Long containerId, Instant scanCreatedAt) {}

    private static Copied copied(Connection connection, long scanId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select repo_id, container_id, scan_created_at from t_component where scan_id = ?")) {
            statement.setLong(1, scanId);
            try (ResultSet rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                Timestamp at = rows.getTimestamp("scan_created_at");
                Copied copied = new Copied(nullable(rows, "repo_id"), nullable(rows, "container_id"),
                        at == null ? null : at.toInstant());
                assertThat(rows.next()).isFalse();
                return copied;
            }
        }
    }

    private static Instant createdAt(Connection connection, long scanId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("select created_at from t_scan where id = ?")) {
            statement.setLong(1, scanId);
            try (ResultSet rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                return rows.getTimestamp(1).toInstant();
            }
        }
    }

    private static Long nullable(ResultSet rows, String column) throws SQLException {
        long value = rows.getLong(column);
        return rows.wasNull() ? null : value;
    }

    private static long scan(Connection connection, String targetColumn, long target) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("insert into t_scan (branch, status, created_at, "
                + targetColumn + ") values ('main', 'completed', ?, ?)")) {
            statement.setTimestamp(1, Timestamp.from(SCANNED));
            statement.setLong(2, target);
            statement.executeUpdate();
        }
        return lastId(connection, "t_scan");
    }

    private static void component(Connection connection, long scanId, String name) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "insert into t_component (scan_id, name, version) values (?, ?, '1.0')")) {
            statement.setLong(1, scanId);
            statement.setString(2, name);
            statement.executeUpdate();
        }
    }

    /** The row just written: one connection, one writer, so the highest id is it on every engine. */
    private static long insert(Connection connection, String sql, String table) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(sql);
        }
        return lastId(connection, table);
    }

    private static long lastId(Connection connection, String table) throws SQLException {
        try (Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("select max(id) from " + table)) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static void migrate(String target) {
        MigrationDialect dialect = switch (ENGINE) {
            case POSTGRES -> MigrationDialect.POSTGRESQL;
            case MYSQL -> MigrationDialect.MYSQL;
        };
        var configuration = Flyway.configure()
                .locations(dialect.locations().toArray(String[]::new))
                .placeholders(dialect.placeholders());
        configuration.dataSource(CONTAINER.getJdbcUrl(), CONTAINER.getUsername(), CONTAINER.getPassword());
        if (target != null) {
            configuration.target(target);
        }
        configuration.load().migrate();
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(CONTAINER.getJdbcUrl(), CONTAINER.getUsername(), CONTAINER.getPassword());
    }
}

package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.config.MigrationDialect;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * V70 moves every target with no schedule to the default interval, and stamps it with the upgrade so
 * that its first round is its own moment in the following week (0.11.0).
 *
 * <p>Written twice, once per engine, because "now, in UTC" is spelled differently: a spelling that wrote
 * the session's local time on MySQL would stamp every target hours off, and one that wrote nothing would
 * leave the whole estate due in the first minute after the upgrade — the crowd the stamp exists to
 * prevent. Neither shows on the fresh databases the other suites start from, where the migration finds
 * no target. So this builds the schema up to V69, writes the targets an installation held then, applies
 * the rest, and reads the rows back.
 *
 * <p>Flyway alone, with the application's locations and placeholders for the engine, as {@code
 * ScoreFormulaChangedOnIntegrationTest} does.
 */
@DisplayName("the default scan schedule, written at the upgrade")
class DefaultScanScheduleIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    private static final Instant LONG_AGO = Instant.parse("2026-01-05T03:00:00Z");

    @BeforeAll
    static void start() {
        CONTAINER.start();
    }

    @AfterAll
    static void stop() {
        CONTAINER.stop();
    }

    @Test
    @DisplayName("a target with no schedule is stamped with the upgrade, in UTC; a scheduled one keeps its stamp; none is manual only")
    void stampsTheUnscheduled() throws Exception {
        flyway(null).clean();
        flyway("69").migrate();
        long unscheduled;
        long zeroInterval;
        long interval;
        long cron;
        long image;
        try (Connection connection = connect()) {
            unscheduled = repository(connection, null, null, null);
            zeroInterval = repository(connection, 0, " ", LONG_AGO);
            interval = repository(connection, 60, null, LONG_AGO);
            cron = repository(connection, null, "0 2 * * *", LONG_AGO);
            image = container(connection);
        }
        Instant before = Instant.now().minusSeconds(1);
        flyway(null).migrate();
        Instant after = Instant.now().plusSeconds(1);

        try (Connection connection = connect()) {
            assertThat(stamp(connection, "t_repository", unscheduled)).hasValueSatisfying(at -> assertThat(at).isBetween(before, after));
            assertThat(stamp(connection, "t_repository", zeroInterval)).hasValueSatisfying(at -> assertThat(at).isBetween(before, after));
            assertThat(stamp(connection, "t_container", image)).hasValueSatisfying(at -> assertThat(at).isBetween(before, after));
            // A target with a schedule of its own runs as it always has: its last round is untouched.
            assertThat(stamp(connection, "t_repository", interval)).contains(LONG_AGO);
            assertThat(stamp(connection, "t_repository", cron)).contains(LONG_AGO);
            // Nobody's earlier wish for "manual" can be read off a row, so nobody is manual only.
            try (PreparedStatement statement = connection.prepareStatement(
                            "select count(*) from t_repository where scan_manual_only = true");
                    ResultSet rows = statement.executeQuery()) {
                rows.next();
                assertThat(rows.getLong(1)).isZero();
            }
        }
    }

    private static long repository(Connection connection, Integer interval, String cron, Instant lastScheduled)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "insert into t_repository (url, branch, scan_interval_minutes, scan_cron, last_scheduled_scan_at, tier,"
                        + " in_certified_scope) values (?, 'main', ?, ?, ?, 'TIER_2_BUSINESS_OPERATIONAL', false)",
                new String[] {"id"})) {
            statement.setString(1, "https://example.invalid/" + System.nanoTime() + ".git");
            statement.setObject(2, interval);
            statement.setString(3, cron);
            statement.setObject(4, lastScheduled == null ? null : utc(lastScheduled));
            statement.executeUpdate();
            return generated(statement);
        }
    }

    private static long container(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "insert into t_container (image_name, tag, tier, in_certified_scope)"
                        + " values ('team/service', 'latest', 'TIER_2_BUSINESS_OPERATIONAL', false)",
                new String[] {"id"})) {
            statement.executeUpdate();
            return generated(statement);
        }
    }

    private static long generated(PreparedStatement statement) throws SQLException {
        try (ResultSet keys = statement.getGeneratedKeys()) {
            keys.next();
            return keys.getLong(1);
        }
    }

    /**
     * The stored instant, read as the application reads it: a UTC wall time on MySQL's {@code
     * datetime(6)}, an instant on PostgreSQL's {@code timestamp with time zone}.
     */
    private static Optional<Instant> stamp(Connection connection, String table, long id) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select last_scheduled_scan_at from " + table + " where id = ?")) {
            statement.setLong(1, id);
            try (ResultSet rows = statement.executeQuery()) {
                rows.next();
                return switch (ENGINE) {
                    case MYSQL -> Optional.ofNullable(rows.getObject(1, LocalDateTime.class))
                            .map(at -> at.toInstant(ZoneOffset.UTC));
                    case POSTGRES -> Optional.ofNullable(rows.getObject(1, java.time.OffsetDateTime.class))
                            .map(java.time.OffsetDateTime::toInstant);
                };
            }
        }
    }

    /** What the application writes for an instant, as {@link #stamp} reads it back. */
    private static Object utc(Instant at) {
        return switch (ENGINE) {
            case MYSQL -> LocalDateTime.ofInstant(at, ZoneOffset.UTC);
            case POSTGRES -> at.atOffset(ZoneOffset.UTC);
        };
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

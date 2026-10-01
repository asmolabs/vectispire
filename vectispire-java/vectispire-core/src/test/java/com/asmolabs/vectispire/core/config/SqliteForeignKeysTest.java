package com.asmolabs.vectispire.core.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.zaxxer.hikari.HikariDataSource;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The pragma that makes SQLite's foreign keys mean something, on a pool of its own.
 *
 * <p><b>SQLite records an {@code on delete cascade} and enforces nothing</b> until a connection
 * issues {@code PRAGMA foreign_keys = ON}; {@link SqliteForeignKeys} sets it as the pool's init SQL,
 * because the pragma is per connection. This was asked of the context's pool while the suite ran
 * on SQLite; the suite runs on MySQL now (decision 0034), so the pool is built here, and the class
 * and this test leave together with the engine.
 */
@DisplayName("SQLite's foreign keys are switched on for every pooled connection")
class SqliteForeignKeysTest {

    @TempDir
    Path scratch;

    @Test
    @DisplayName("the pragma is on, on a connection the pool handed out")
    void thePragmaIsOn() throws Exception {
        try (HikariDataSource pool = new HikariDataSource()) {
            pool.setJdbcUrl("jdbc:sqlite:" + scratch.resolve("keys.db"));
            new SqliteForeignKeys().postProcessAfterInitialization(pool, "dataSource");

            // Asked of a pooled connection rather than of the configuration, because the setting is
            // only worth anything if it survived the trip through Hikari.
            try (Connection connection = pool.getConnection();
                 Statement statement = connection.createStatement();
                 ResultSet answer = statement.executeQuery("pragma foreign_keys")) {
                assertThat(answer.next()).isTrue();
                assertThat(answer.getInt(1))
                        .as("SQLite enforces nothing without it, whatever the schema declares")
                        .isEqualTo(1);
            }
        }
    }
}

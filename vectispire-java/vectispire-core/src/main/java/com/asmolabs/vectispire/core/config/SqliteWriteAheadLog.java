package com.asmolabs.vectispire.core.config;

import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Lets a reader read while a writer writes, which SQLite does not do by default.
 *
 * <p><b>Measured, not assumed.</b> A single session of the browser suite produced <b>1015</b>
 * {@code SQLITE_BUSY}, the first nine seconds after start-up. Each leaves as a {@code 500}: a
 * refused sign-in, a lost triage, a screen saying "failed" with no readable reason. This is not
 * test flakiness — the suite only exposes what a second person in front of the application would
 * trigger on the single-file deployment.
 *
 * <p><b>The cause is the journal mode.</b> In {@code delete}, the default, a write takes an
 * exclusive lock on the whole file: every concurrent read waits, and past the busy timeout it
 * fails. In {@code WAL}, reads carry on during the write, which removes nearly all of these
 * collisions.
 *
 * <p><b>Once, not per connection.</b> The journal mode is a property <em>of the file</em>: set
 * once, it survives restarts. That is why it is not in {@link SqliteForeignKeys}'s
 * {@code connectionInitSql} — and just as well, because that slot can carry only one statement:
 * {@code sqlite-jdbc} runs only the first of a multi-statement {@code execute}, silently. Two
 * pragmas separated by a semicolon would have left the second with no effect, while looking like
 * the opposite.
 *
 * <p><b>After start-up, not during.</b> Setting the pragma as the data source is built would open
 * the first connection too early, before Flyway has migrated.
 */
@Component
class SqliteWriteAheadLog {

    private static final Logger log = LoggerFactory.getLogger(SqliteWriteAheadLog.class);
    private static final String SQLITE = "jdbc:sqlite";

    private final DataSource dataSource;

    SqliteWriteAheadLog(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @EventListener(ApplicationReadyEvent.class)
    void enable() {
        if (!(dataSource instanceof HikariDataSource pool)
                || pool.getJdbcUrl() == null
                || !pool.getJdbcUrl().startsWith(SQLITE)) {
            return;
        }

        try (Connection connection = pool.getConnection();
             Statement statement = connection.createStatement()) {
            // The pragma answers with the mode it settled on, and that is the only proof it took:
            // on a read-only file, or on a network mount, SQLite refuses WAL and stays in `delete`
            // without raising an error.
            var result = statement.executeQuery("PRAGMA journal_mode = WAL");
            String mode = result.next() ? result.getString(1) : "unknown";
            if ("wal".equalsIgnoreCase(mode)) {
                log.info("SQLite: journal in WAL, reads no longer block behind a write.");
            } else {
                log.warn("SQLite: WAL refused, the journal stays in '{}' — concurrent writes will "
                        + "go on producing SQLITE_BUSY.", mode);
            }
        } catch (SQLException failure) {
            log.warn("SQLite: impossible de passer le journal en WAL.", failure);
        }
    }
}

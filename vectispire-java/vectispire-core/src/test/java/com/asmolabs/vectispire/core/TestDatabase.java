package com.asmolabs.vectispire.core;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * The MySQL server the context and HTTP suites run on, and the one database this JVM uses on it
 * (decision 0034).
 *
 * <p><b>MySQL because it is the engine {@code docker-compose.yml} ships.</b> The suite ran on a
 * SQLite file for as long as needing no daemon outweighed the rest; what it cost was a schema
 * Hibernate never validated in this suite, locking no deployment has, and a defect class — a
 * statement SQLite accepts and the engines refuse, a bound column SQLite does not bound — that no
 * assertion here could see.
 *
 * <p><b>Where the server comes from.</b> {@code VECTISPIRE_TEST_DB_URL} — a server URL with no
 * database, {@code jdbc:mysql://mysql:3306} — names one that is already running: CI's {@code jvm}
 * job has it as a job service beside it, with no Docker socket in the job. Without it, one
 * container per test JVM through Testcontainers, the image the campaign pins for MySQL ({@code
 * Engine.MYSQL}, under {@code src/integrationTest}, which this source set cannot see — so the two
 * are kept equal by hand, and a difference is a suite and a campaign disagreeing about the engine).
 *
 * <p><b>No daemon and no URL is a failure, not a skip.</b> A suite that skips itself reports green
 * having checked nothing (AGENTS.md); the message says how to give it a server.
 *
 * <p><b>One database per JVM, migrated once.</b> A database per Spring context, as the SQLite file
 * was, would run the 64 migrations again for each of the suite's nearly thirty contexts — two
 * seconds each on MySQL when measured, a minute added to a suite of two. So the contexts share it,
 * and what a fresh file gave each of them — no row left by somebody else when it starts — {@link
 * #emptyBeforeAContextStarts} gives instead.
 */
public final class TestDatabase {

    /** The campaign's pin, {@code Engine.MYSQL}. */
    static final String IMAGE = "mysql:9.4";

    private static final String URL_VARIABLE = "VECTISPIRE_TEST_DB_URL";
    private static final String USER_VARIABLE = "VECTISPIRE_TEST_DB_USER";
    private static final String PASSWORD_VARIABLE = "VECTISPIRE_TEST_DB_PASSWORD";

    private TestDatabase() {}

    /** The server's address and an account that may create a database on it. */
    private record Server(String url, String user, String password) {

        Connection connect(String database) throws SQLException {
            return DriverManager.getConnection(url + "/" + database, user, password);
        }
    }

    /** This JVM's database on its server. */
    private record Database(Server server, String name) {

        String url() {
            return server.url() + "/" + name;
        }

        Connection connect() throws SQLException {
            return server.connect(name);
        }
    }

    private static Database database;
    private static IllegalStateException unavailable;

    /**
     * Opened on first use and kept for the JVM, so a class that never touches the database starts no
     * server — and its failure kept too. A static initialiser would report the reason to the first
     * class only and a bare {@code NoClassDefFoundError} to the two hundred after it, each of which
     * would then read as a defect of its own.
     */
    private static synchronized Database database() {
        if (unavailable != null) {
            throw new IllegalStateException(unavailable.getMessage(), unavailable);
        }
        if (database == null) {
            try {
                Server server = server();
                database = new Database(server, createDatabase(server));
            } catch (RuntimeException failed) {
                unavailable = failed instanceof IllegalStateException refused
                        ? refused
                        : new IllegalStateException(
                                "Could not start the test database: " + failed.getMessage(), failed);
                throw unavailable;
            }
        }
        return database;
    }

    /** Points a context at this JVM's database. */
    public static void register(DynamicPropertyRegistry registry) {
        Database opened = database();
        registry.add("spring.datasource.url", opened::url);
        registry.add("spring.datasource.username", opened.server()::user);
        registry.add("spring.datasource.password", opened.server()::password);
    }

    /**
     * Empties the tables before a context starts on the database another one used.
     *
     * <p>A context runs code at start-up — the repairs and resumptions an {@code
     * ApplicationReadyEvent} triggers — and on the SQLite file each one ran on a database nobody had
     * touched. Shared, it would run on whatever the last test left, and a resumed purge or a repair
     * finding work fails or passes by the order the classes ran in. Called from the property source,
     * which Spring invokes when it builds a context and not when it reuses a cached one; before the
     * first migration there is nothing to empty.
     */
    static void emptyBeforeAContextStarts(List<String> tablesChildrenFirst) {
        empty(tablesChildrenFirst, true);
    }

    /** Empties the tables, in the order given, before a test. */
    static void empty(List<String> tablesChildrenFirst) {
        empty(tablesChildrenFirst, false);
    }

    private static Connection cleaner;

    /**
     * <b>One round trip and one commit, on a connection of the fixture's own.</b> Sixty deletes sent
     * one by one through the application's pool, each its own commit, cost some twenty seconds of the
     * suite's run against a container, measured. The multi-statement switch that sends them together is
     * on this connection alone: on the application's it would let an injected {@code ;} stack a second
     * statement, and the suite would be testing a driver configuration nobody deploys.
     */
    private static synchronized void empty(List<String> tablesChildrenFirst, boolean onlyIfMigrated) {
        Database opened = database();
        try {
            if (cleaner == null || !cleaner.isValid(2)) {
                cleaner = DriverManager.getConnection(
                        opened.url() + "?allowMultiQueries=true", opened.server().user(), opened.server().password());
            }
            if (onlyIfMigrated && !migrated(cleaner, opened.name())) {
                return;
            }
            StringBuilder statements = new StringBuilder("start transaction;");
            tablesChildrenFirst.forEach(table -> statements.append("delete from ").append(table).append(';'));
            statements.append("commit");
            try (Statement statement = cleaner.createStatement()) {
                statement.execute(statements.toString());
                // The server stops at the first refused delete, and the driver reports the refusal only
                // when that statement's result is read: unread, rows would stay behind in silence.
                while (statement.getMoreResults() || statement.getUpdateCount() != -1) {
                    // Each result is a delete's count; reading them is what surfaces an error.
                }
            }
        } catch (SQLException failed) {
            // Closed rather than kept: a delete refused mid-way leaves the transaction open, holding
            // the locks of the rows already deleted, and every test after it would wait on them.
            close();
            throw new IllegalStateException("Could not empty the test database " + opened.name(), failed);
        }
    }

    private static void close() {
        try {
            if (cleaner != null) {
                cleaner.close();
            }
        } catch (SQLException ignored) {
            // Discarded either way; the next cleaning opens another.
        } finally {
            cleaner = null;
        }
    }

    private static boolean migrated(Connection connection, String name) throws SQLException {
        try (ResultSet tables = connection.getMetaData().getTables(name, null, "flyway_schema_history", null)) {
            return tables.next();
        }
    }

    private static Server server() {
        Optional<String> configured = Optional.ofNullable(System.getenv(URL_VARIABLE)).filter(url -> !url.isBlank());
        if (configured.isPresent()) {
            return new Server(
                    configured.get().replaceAll("/+$", ""),
                    Optional.ofNullable(System.getenv(USER_VARIABLE)).orElse("root"),
                    Optional.ofNullable(System.getenv(PASSWORD_VARIABLE)).orElse(""));
        }
        if (!DockerClientFactory.instance().isDockerAvailable()) {
            throw new IllegalStateException("The context and HTTP suites run on MySQL (decision 0034), and there is "
                    + "neither a Docker daemon to start " + IMAGE + " in nor a server named by " + URL_VARIABLE
                    + " (with " + USER_VARIABLE + " and " + PASSWORD_VARIABLE + "). Start Docker, or point "
                    + URL_VARIABLE + " at a MySQL server, e.g. jdbc:mysql://localhost:3306.");
        }
        // Left running until the JVM exits, when Testcontainers' reaper removes it: one container for
        // the whole run, whatever the number of contexts. `withReuse` keeps it across runs too, on a
        // machine whose ~/.testcontainers.properties allows it — hence a database per JVM, not one name.
        MySQLContainer container = new MySQLContainer(DockerImageName.parse(IMAGE)).withReuse(true);
        container.start();
        return new Server(
                "jdbc:mysql://" + container.getHost() + ":" + container.getMappedPort(MySQLContainer.MYSQL_PORT),
                "root",
                container.getPassword());
    }

    private static String createDatabase(Server server) {
        String name = "vectispire_test_" + HexFormat.of().toHexDigits(ThreadLocalRandom.current().nextLong());
        try (Connection connection = server.connect("");
             Statement statement = connection.createStatement()) {
            // Every cached context keeps its own pool, ten connections when busy: sixteen of them
            // pass the server's default of 151, and the context that asks for the 152nd fails to
            // start, blamed on whichever bean opened it. The server's setting, not the pool's: the
            // pool's size is production's, and a test that needs ten connections should have them.
            statement.execute("set global max_connections = 1000");
            // Every commit flushes the redo log and the binary log to disk by default; the suite
            // commits tens of thousands of times and never survives a crash of the server. What it
            // asserts — isolation, locking, constraints, types — is the same either way.
            statement.execute("set global innodb_flush_log_at_trx_commit = 2");
            statement.execute("set global sync_binlog = 0");
            statement.execute("create database " + name);
        } catch (SQLException failed) {
            throw new IllegalStateException("Could not create the test database on " + server.url(), failed);
        }
        Runtime.getRuntime().addShutdownHook(new Thread(() -> drop(server, name), "drop-" + name));
        return name;
    }

    /** A server somebody keeps — CI's service, a reused container — should not fill up run after run. */
    private static void drop(Server server, String name) {
        try (Connection connection = server.connect("");
             Statement statement = connection.createStatement()) {
            // A connection a closing context still holds would make the drop wait on its lock for the
            // server's default of a year, and the JVM would never exit.
            statement.execute("set session lock_wait_timeout = 5");
            statement.execute("drop database if exists " + name);
        } catch (SQLException ignored) {
            // The container may already be gone; nothing is left to drop then.
        }
    }
}

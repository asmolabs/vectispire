package com.asmolabs.vectispire.core;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.exception.ConflictException;
import com.github.dockerjava.api.exception.NotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.TestcontainersConfiguration;

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
 * On a machine that allows Testcontainers' reuse, that container is kept across runs and shared by
 * every worktree — {@code vectispire-test-mysql}, see {@code ReusedContainer} — and nothing waits
 * on its start but the first run.
 *
 * <p><b>No daemon and no URL is a failure, not a skip.</b> A suite that skips itself reports green
 * having checked nothing (AGENTS.md); the message says how to give it a server.
 *
 * <p><b>One database per JVM, migrated once.</b> A database per Spring context, as the SQLite file
 * was, would run the 64 migrations again for each of the suite's nearly thirty contexts — two
 * seconds each on MySQL when measured, a minute added to a suite of two. So the contexts share it,
 * and what a fresh file gave each of them — no row left by somebody else when it starts — {@link
 * #emptyBeforeAContextStarts} gives instead.
 *
 * <p><b>Dropped when the JVM ends, and swept when it did not.</b> A server somebody keeps — the
 * reused container, the one {@code VECTISPIRE_TEST_DB_URL} names — would otherwise gather a database
 * per run. The shutdown hook drops this JVM's and any scratch a test left open; a JVM killed before
 * its hook ran leaves its own, which the next JVM to start drops once it is a day old ({@link
 * TestDatabaseNames}). Every name is new to its JVM, and Flyway migrates each database alone, so two
 * JVMs starting at once on one server share nothing but the server.
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
     * A database of its own on the suite's server, for a test that migrates one from nothing; dropped
     * when closed. The shared one is already migrated, and a migration test run on it proves nothing.
     */
    public record Scratch(String url, String user, String password) implements AutoCloseable {

        @Override
        public void close() {
            Database opened = database();
            String name = url.substring(url.lastIndexOf('/') + 1);
            drop(opened.server(), name);
            UNCLOSED_SCRATCHES.remove(name);
        }
    }

    /** Dropped by the shutdown hook if a test ends without closing them — a reused server keeps them otherwise. */
    private static final Set<String> UNCLOSED_SCRATCHES = ConcurrentHashMap.newKeySet();

    /** A fresh, empty database for one test — see {@link Scratch}. */
    public static Scratch scratch() {
        Database opened = database();
        String name = TestDatabaseNames.name(
                TestDatabaseNames.SCRATCH, Instant.now(), ThreadLocalRandom.current().nextLong());
        try (Connection connection = opened.server().connect("");
             Statement statement = connection.createStatement()) {
            statement.execute("create database " + name);
        } catch (SQLException failed) {
            throw new IllegalStateException("Could not create a scratch database on " + opened.server().url(), failed);
        }
        UNCLOSED_SCRATCHES.add(name);
        return new Scratch(opened.server().url() + "/" + name, opened.server().user(), opened.server().password());
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
            Server named = new Server(
                    configured.get().replaceAll("/+$", ""),
                    Optional.ofNullable(System.getenv(USER_VARIABLE)).orElse("root"),
                    Optional.ofNullable(System.getenv(PASSWORD_VARIABLE)).orElse(""));
            // Swept like a reused container: a developer's own server outlives the JVMs a kill left
            // behind, and only names that carry this class's prefix and instant are touched — CI's
            // service is new for every job and simply has none.
            sweepOrphans(named);
            return named;
        }
        if (!DockerClientFactory.instance().isDockerAvailable()) {
            throw new IllegalStateException("The context and HTTP suites run on MySQL (decision 0034), and there is "
                    + "neither a Docker daemon to start " + IMAGE + " in nor a server named by " + URL_VARIABLE
                    + " (with " + USER_VARIABLE + " and " + PASSWORD_VARIABLE + "). Start Docker, or point "
                    + URL_VARIABLE + " at a MySQL server, e.g. jdbc:mysql://localhost:3306.");
        }
        boolean reused = TestcontainersConfiguration.getInstance().environmentSupportsReuse();
        MySQLContainer container = reused ? ReusedContainer.start() : started(new MySQLContainer(DockerImageName.parse(IMAGE)));
        Server started = new Server(
                "jdbc:mysql://" + container.getHost() + ":" + container.getMappedPort(MySQLContainer.MYSQL_PORT),
                "root",
                container.getPassword());
        if (reused) {
            sweepOrphans(started);
        }
        return started;
    }

    private static MySQLContainer started(MySQLContainer container) {
        container.start();
        return container;
    }

    /**
     * The container a machine keeps across runs and worktrees, when it allows reuse ({@code
     * testcontainers.reuse.enable=true} in {@code ~/.testcontainers.properties}, or {@code
     * TESTCONTAINERS_REUSE_ENABLE=true}). Without that, one container per JVM that Testcontainers'
     * reaper removes when the JVM exits — what every run did before, and what nobody has to opt out of.
     *
     * <p><b>Reuse is Testcontainers' match on a hash of the create command</b> — image, environment,
     * labels, Testcontainers' version; not the name, which travels outside the command's body — of a
     * <em>running</em> container. So the label is a constant, or every run would make a container
     * nobody matches again. The name buys more than identification: it is the lock Testcontainers
     * lacks ("TODO locking" in {@code findContainerForReuse}). Two JVMs starting at once both find
     * nothing and both create; without a name each gets a container of its own, and the second
     * lingers for ever. With it, the daemon refuses the second create, and that JVM retries until the
     * first one's container runs, then matches it.
     *
     * <p><b>A refused create is read from what holds the name</b>, never assumed to be the winner:
     * stopped (Docker restarted — reuse never starts a stopped container) and labelled ours, it is
     * removed; another image or another Testcontainers version — another branch's configuration, maybe
     * in use by a run in another worktree — is left alone and this run uses a reusable container
     * without the name, saying how to clean up. Nothing running is ever removed.
     */
    private static final class ReusedContainer {

        static final String NAME = "vectispire-test-mysql";
        static final String LABEL = "com.asmolabs.vectispire.test";

        /** A create still in progress next door runs within seconds; past this the holder is no peer. */
        private static final Duration PEER_STARTS_WITHIN = Duration.ofMinutes(2);

        private static final Logger log = LoggerFactory.getLogger(TestDatabase.class);

        static MySQLContainer start() {
            Instant deadline = Instant.now().plus(PEER_STARTS_WITHIN);
            String holderImage = "?";
            boolean sawItRunning = false;
            while (Instant.now().isBefore(deadline)) {
                try {
                    return started(reusable().withCreateContainerCmdModifier(create -> create.withName(NAME)));
                } catch (RuntimeException failed) {
                    if (!nameTaken(failed)) {
                        throw failed;
                    }
                }
                Optional<InspectContainerResponse> holder = holder();
                if (holder.isEmpty()) {
                    continue; // Removed between the refusal and the look.
                }
                InspectContainerResponse found = holder.get();
                Map<String, String> labels = Optional.ofNullable(found.getConfig().getLabels()).orElse(Map.of());
                holderImage = found.getConfig().getImage();
                boolean ours = "mysql".equals(labels.get(LABEL));
                boolean running = Boolean.TRUE.equals(found.getState().getRunning());
                if (ours && !running && !"created".equals(found.getState().getStatus())) {
                    remove(found.getId());
                    continue;
                }
                boolean sameConfiguration = IMAGE.equals(holderImage) && Objects.equals(
                        DockerClientFactory.TESTCONTAINERS_VERSION,
                        labels.get(DockerClientFactory.TESTCONTAINERS_VERSION_LABEL));
                // Running, it would have matched this round's search, which reads running containers by
                // hash: refused twice by a running holder means another hash — this class's own create
                // command changed since it was made — and waiting longer will not change that.
                if (!ours || !sameConfiguration || (running && sawItRunning)) {
                    break;
                }
                sawItRunning |= running;
                pause(); // A peer's container, created and not yet matched: the next round finds it.
            }
            log.warn("The container named {} ({}) is not this configuration's ({}, Testcontainers {}), so this run "
                    + "reuses one without the name. Remove the old one once no run uses it: docker rm -f {}",
                    NAME, holderImage, IMAGE, DockerClientFactory.TESTCONTAINERS_VERSION, NAME);
            return started(reusable());
        }

        private static MySQLContainer reusable() {
            return new MySQLContainer(DockerImageName.parse(IMAGE)).withReuse(true).withLabel(LABEL, "mysql");
        }

        /** The daemon's 409, wherever Testcontainers wrapped it. */
        private static boolean nameTaken(Throwable failed) {
            for (Throwable cause = failed; cause != null; cause = cause.getCause()) {
                if (cause instanceof ConflictException) {
                    return true;
                }
            }
            return false;
        }

        private static Optional<InspectContainerResponse> holder() {
            try {
                return Optional.of(DockerClientFactory.instance().client().inspectContainerCmd(NAME).exec());
            } catch (NotFoundException gone) {
                return Optional.empty();
            }
        }

        private static void remove(String id) {
            try {
                // Not forced: had a peer just started it, the daemon refuses, and the next round reuses it.
                DockerClientFactory.instance().client().removeContainerCmd(id).exec();
            } catch (NotFoundException | ConflictException raced) {
                // Gone or started meanwhile; the next round reads it again.
            }
        }

        private static void pause() {
            try {
                Thread.sleep(500);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for " + NAME, interrupted);
            }
        }
    }

    /**
     * Drops the databases a killed JVM left on a server somebody keeps: this class's names only, and
     * only once {@link TestDatabaseNames#ORPHANED_AFTER} old, so a run in progress elsewhere — another
     * worktree on the same container — keeps its own. Two JVMs sweeping at once drop with {@code if
     * exists}; a sweep that fails costs disk, not the run.
     */
    private static void sweepOrphans(Server server) {
        List<String> names = new ArrayList<>();
        try (Connection connection = server.connect("");
             Statement statement = connection.createStatement();
             ResultSet found = statement.executeQuery(
                     "select schema_name from information_schema.schemata where schema_name like 'vectispire\\_%'")) {
            while (found.next()) {
                names.add(found.getString(1));
            }
        } catch (SQLException failed) {
            return;
        }
        TestDatabaseNames.orphans(names, Instant.now()).forEach(orphan -> drop(server, orphan));
    }

    private static String createDatabase(Server server) {
        String name = TestDatabaseNames.name(
                TestDatabaseNames.SHARED, Instant.now(), ThreadLocalRandom.current().nextLong());
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
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            drop(server, name);
            List.copyOf(UNCLOSED_SCRATCHES).forEach(scratch -> drop(server, scratch));
        }, "drop-" + name));
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

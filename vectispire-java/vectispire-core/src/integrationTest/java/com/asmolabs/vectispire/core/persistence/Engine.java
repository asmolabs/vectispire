package com.asmolabs.vectispire.core.persistence;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Optional;
import org.testcontainers.containers.JdbcDatabaseContainer;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Which engine the campaign is running against, and what that engine can be asked to prove.
 *
 * <p><b>The four are not interchangeable, and pretending they are is how a portability defect
 * survives.</b> Three have real column types, so Hibernate can be asked to validate the
 * entities against the schema the migrations built. SQLite has affinities instead — {@code
 * datetime} is stored as TEXT — so a type comparison there measures how the migration happened to
 * spell the column rather than whether the mapping works. It is proven by writing a row and reading it back, which is
 * the property that actually matters.
 *
 * <p>The concrete containers live in a package per module since Testcontainers 2: the classes
 * of the same name under {@code org.testcontainers.containers} are the deprecated 1.x ones,
 * still present and still compiling, which is how a build silently keeps using them.
 *
 * <p>The images are pinned. A campaign that silently moved to a new minor version would turn
 * "this engine changed its behaviour" into "the build broke this morning".
 */
public enum Engine {
    POSTGRES("postgres:17.6-alpine", true),
    MYSQL("mysql:9.4", true),

    /** No container, no strict validation — see the class comment. */
    SQLITE(null, false);

    private final String image;
    private final boolean typed;

    Engine(String image, boolean typed) {
        this.image = image;
        this.typed = typed;
    }

    /** Whether Hibernate can be asked to validate column types against this engine. */
    public boolean supportsStrictValidation() {
        return typed;
    }

    /** The engine named by {@code -Pdialect}, defaulting to the one deployments use. */
    public static Engine selected() {
        String name = System.getProperty("vectispire.db.dialect", "postgres").toUpperCase(Locale.ROOT);
        try {
            return valueOf(name);
        } catch (IllegalArgumentException unknown) {
            throw new IllegalArgumentException(
                    "Unknown dialect \"" + name.toLowerCase(Locale.ROOT) + "\". Expected one of: postgres, mysql, "
                            + "sqlite.");
        }
    }

    public Optional<JdbcDatabaseContainer<?>> container() {
        DockerImageName reference = image == null ? null : DockerImageName.parse(image);
        return switch (this) {
            case POSTGRES -> Optional.of(new PostgreSQLContainer(reference));
            case MYSQL -> Optional.of(new MySQLContainer(reference));
            case SQLITE -> Optional.empty();
        };
    }

    /**
     * Points a Spring context at the selected engine.
     *
     * <p>Shared by every suite in the campaign, so that "which engine am I on" is decided once
     * — two suites configuring it apart is how one of them quietly runs on the wrong one.
     */
    public static void configure(Engine engine, Optional<JdbcDatabaseContainer<?>> container,
            org.springframework.test.context.DynamicPropertyRegistry registry) {

        // **The application's own background jobs are switched off.** The campaign starts the
        // whole application, and `@Scheduled(fixedDelay=…)` runs its first execution immediately
        // — so the scheduler took the leader lease in the middle of the test that asserts who
        // holds it, roughly one run in three. An intermittent failure whose cause is the
        // application competing with its own test is the least debuggable kind there is, and it
        // reads as a flaky engine rather than as this.
        registry.add("vectispire.worker.enabled", () -> "false");
        registry.add("vectispire.jobs.relay-interval", () -> "24h");
        registry.add("vectispire.jobs.scheduler-interval", () -> "24h");
        registry.add("vectispire.jobs.maintenance-interval", () -> "24h");
        // The interval alone was not enough, and that is the whole lesson: `fixedDelay` spaces
        // the runs that *follow* and lets the first one fire the moment the context is ready.
        // The lease was taken in the middle of the test asserting who held it, on two runs in
        // five, and the message named a random instance id nobody could trace to a scheduler.
        registry.add("vectispire.jobs.initial-delay", () -> "24h");
        registry.add("vectispire.worker.initial-delay", () -> "24h");

        container.ifPresentOrElse(
                started -> {
                    registry.add("spring.datasource.url", started::getJdbcUrl);
                    registry.add("spring.datasource.username", started::getUsername);
                    registry.add("spring.datasource.password", started::getPassword);
                    registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
                },
                () -> {
                    registry.add("spring.datasource.url", () -> "jdbc:sqlite:" + sqliteFile());
                    registry.add("spring.datasource.username", () -> "");
                    registry.add("spring.datasource.password", () -> "");
                    registry.add("spring.jpa.database-platform",
                            () -> "org.hibernate.community.dialect.SQLiteDialect");
                    registry.add("spring.jpa.hibernate.ddl-auto", () -> "none");
                });
    }

    /** Where SQLite keeps its file for a run. Fresh each time, so nothing carries over. */
    public static Path sqliteFile() {
        Path file = Path.of(System.getProperty("java.io.tmpdir"), "vectispire-campaign.db");
        file.toFile().delete();
        return file;
    }
}

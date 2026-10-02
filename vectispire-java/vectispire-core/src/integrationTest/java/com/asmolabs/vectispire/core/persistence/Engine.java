package com.asmolabs.vectispire.core.persistence;

import java.util.Locale;
import org.testcontainers.containers.JdbcDatabaseContainer;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Which engine the campaign is running against.
 *
 * <p><b>The two are not interchangeable, and pretending they are is how a portability defect
 * survives.</b> Both have real column types, so Hibernate validates the entities against the schema
 * the migrations built on each. A third leg ran the SQLite fixture the HTTP suite used, which had
 * affinities rather than types; it went with that fixture (decision 0034).
 *
 * <p>The concrete containers live in a package per module since Testcontainers 2: the classes
 * of the same name under {@code org.testcontainers.containers} are the deprecated 1.x ones,
 * still present and still compiling, which is how a build silently keeps using them.
 *
 * <p>The images are pinned. A campaign that silently moved to a new minor version would turn
 * "this engine changed its behaviour" into "the build broke this morning". MySQL's is also the unit
 * suite's ({@code TestDatabase.IMAGE}) and CI's job services': kept equal by hand.
 */
public enum Engine {
    POSTGRES("postgres:17.6-alpine"),
    MYSQL("mysql:9.4");

    private final String image;

    Engine(String image) {
        this.image = image;
    }

    /** The engine named by {@code -Pdialect}, defaulting to the one deployments use. */
    public static Engine selected() {
        String name = System.getProperty("vectispire.db.dialect", "postgres").toUpperCase(Locale.ROOT);
        try {
            return valueOf(name);
        } catch (IllegalArgumentException unknown) {
            throw new IllegalArgumentException(
                    "Unknown dialect \"" + name.toLowerCase(Locale.ROOT) + "\". Expected one of: postgres, mysql.");
        }
    }

    public JdbcDatabaseContainer<?> container() {
        DockerImageName reference = DockerImageName.parse(image);
        return switch (this) {
            case POSTGRES -> new PostgreSQLContainer(reference);
            case MYSQL -> new MySQLContainer(reference);
        };
    }

    /**
     * Points a Spring context at the selected engine.
     *
     * <p>Shared by every suite in the campaign, so that "which engine am I on" is decided once
     * — two suites configuring it apart is how one of them quietly runs on the wrong one.
     */
    public static void configure(Engine engine, JdbcDatabaseContainer<?> container,
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

        registry.add("spring.datasource.url", container::getJdbcUrl);
        registry.add("spring.datasource.username", container::getUsername);
        registry.add("spring.datasource.password", container::getPassword);
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
    }
}

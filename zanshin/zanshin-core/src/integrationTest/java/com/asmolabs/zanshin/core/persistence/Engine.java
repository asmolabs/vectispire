package com.asmolabs.zanshin.core.persistence;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Optional;
import org.testcontainers.containers.JdbcDatabaseContainer;
import org.testcontainers.mariadb.MariaDBContainer;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Which engine the campaign is running against, and what that engine can be asked to prove.
 *
 * <p><b>The four are not interchangeable, and pretending they are is how a portability defect
 * survives.</b> Three have real column types, so Hibernate can be asked to validate the
 * entities against the schema Liquibase built. SQLite has affinities instead — {@code datetime}
 * is stored as TEXT — so a type comparison there measures Liquibase's naming choices rather
 * than whether the mapping works. It is proven by writing a row and reading it back, which is
 * the property that actually matters.
 *
 * <p>The concrete containers live in a package per module since Testcontainers 2: the classes
 * of the same name under {@code org.testcontainers.containers} are the deprecated 1.x ones,
 * still present and still compiling, which is how a build silently keeps using them.
 *
 * <p>The images are pinned. A campaign that silently moved to a new minor version would turn
 * "this engine changed its behaviour" into "the build broke this morning".
 */
enum Engine {
    POSTGRES("postgres:17.6-alpine", true),
    MYSQL("mysql:9.4", true),
    MARIADB("mariadb:11.8", true),

    /** No container, no strict validation — see the class comment. */
    SQLITE(null, false);

    private final String image;
    private final boolean typed;

    Engine(String image, boolean typed) {
        this.image = image;
        this.typed = typed;
    }

    /** Whether Hibernate can be asked to validate column types against this engine. */
    boolean supportsStrictValidation() {
        return typed;
    }

    /** The engine named by {@code -Pdialect}, defaulting to the one deployments use. */
    static Engine selected() {
        String name = System.getProperty("zanshin.db.dialect", "postgres").toUpperCase(Locale.ROOT);
        try {
            return valueOf(name);
        } catch (IllegalArgumentException unknown) {
            throw new IllegalArgumentException(
                    "Unknown dialect \"" + name.toLowerCase(Locale.ROOT) + "\". Expected one of: postgres, mysql, "
                            + "mariadb, sqlite.");
        }
    }

    Optional<JdbcDatabaseContainer<?>> container() {
        DockerImageName reference = image == null ? null : DockerImageName.parse(image);
        return switch (this) {
            case POSTGRES -> Optional.of(new PostgreSQLContainer(reference));
            case MYSQL -> Optional.of(new MySQLContainer(reference));
            case MARIADB -> Optional.of(new MariaDBContainer(reference));
            case SQLITE -> Optional.empty();
        };
    }

    /** Where SQLite keeps its file for a run. Fresh each time, so nothing carries over. */
    static Path sqliteFile() {
        Path file = Path.of(System.getProperty("java.io.tmpdir"), "zanshin-campaign.db");
        file.toFile().delete();
        return file;
    }
}

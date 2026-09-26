package com.asmolabs.vectispire.core.config;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.SequencedMap;

/**
 * The column types a migration may name without naming an engine — the one place they are spelled.
 *
 * <p><b>Why this exists (decision 0027).</b> Decision 0013 chose one native SQL set per engine,
 * because a migration abstraction had hidden where the engines differ. Measured a month later,
 * most of what differed between the three copies of a migration was a type name, and thirteen of
 * the thirty-nine were identical in everything but those names. From V40 on, a migration that
 * differs only by its types is written once, under {@code db/migration/common}, with the
 * placeholders below; the vendor directories keep what genuinely diverges — foreign keys, column
 * changes, date arithmetic, data repairs.
 *
 * <p><b>The concern 0013 raised is answered by keeping the types visible, here.</b> What this
 * table says is exactly what reaches the server, with no translation layer between a reviewer and
 * the DDL:
 *
 * <ul>
 *   <li>{@code ts} is {@code datetime(6)} on MySQL and <b>must stay so</b>. A bare
 *       {@code datetime} truncates to the second, and the audit chain hashes a timestamp
 *       canonicalised to the millisecond: a truncated column makes the log fail its own
 *       integrity verification — a control reporting tampering that never happened. PostgreSQL's
 *       {@code timestamp with time zone} keeps microseconds; SQLite has affinities rather than
 *       types (decision 0014), and {@code numeric} is the spelling its existing set uses.
 *   <li>{@code id} is the whole identity column, {@code primary key} included, so a migration
 *       writes {@code id ${id},} and nothing more. It has to include the key because of SQLite:
 *       only the exact spelling {@code integer primary key} makes the column the rowid, and
 *       {@code autoincrement} is refused anywhere else — {@code bigint primary key autoincrement}
 *       is a syntax error, and {@code integer primary key} without it reuses the id of a deleted
 *       last row. SQLite's integer is 64 bits, so {@code integer} there is MySQL's and
 *       PostgreSQL's {@code bigint}.
 *   <li>{@code bool} is MySQL's {@code bit(1)} — the type Hibernate maps a boolean to on that
 *       engine, so validation compares like with like — whose literals are {@code b'1'} and
 *       {@code b'0'}; hence {@code true} and {@code false} are placeholders too.
 *   <li>{@code text} is MySQL's {@code longtext}: its {@code text} stops at 64 KiB, which a
 *       PostgreSQL {@code text} does not, and a value that fits on one engine only is a 500 on
 *       the other.
 * </ul>
 *
 * <p><b>A value here is as frozen as an applied migration.</b> Flyway does not replay what it has
 * applied, so changing one changes the columns of new installations only, and the two populations
 * diverge without an error. A type change is first a vendor migration altering the existing
 * columns, then an edit of this table.
 *
 * <p>The vendor ids are Spring Boot's {@code DatabaseDriver} ids — the same ones its
 * {@code {vendor}} location placeholder resolves to — so the directory Flyway reads and the types
 * it substitutes are chosen by one question asked of one data source.
 */
public enum MigrationDialect {

    MYSQL("mysql", placeholders(
            "datetime(6)",
            "bigint auto_increment primary key",
            "bit(1)", "b'1'", "b'0'",
            "longtext",
            "double")),

    POSTGRESQL("postgresql", placeholders(
            "timestamp with time zone",
            "bigint generated always as identity primary key",
            "boolean", "true", "false",
            "text",
            "double precision")),

    /** The test fixture (decision 0014): its copy must apply, but nothing is offered on it. */
    SQLITE("sqlite", placeholders(
            "numeric",
            "integer primary key autoincrement",
            "boolean", "1", "0",
            "text",
            "double"));

    /** Read before the vendor's own directory; holds nothing below V40 — see decision 0027. */
    public static final String COMMON_LOCATION = "classpath:db/migration/common";

    private final String vendor;
    private final Map<String, String> placeholders;

    MigrationDialect(String vendor, Map<String, String> placeholders) {
        this.vendor = vendor;
        this.placeholders = placeholders;
    }

    private static Map<String, String> placeholders(
            String ts, String id, String bool, String yes, String no, String text, String dbl) {
        // Positional on purpose: every engine must answer every key, and a constructor that takes
        // seven values cannot forget one the way a map literal per constant could.
        SequencedMap<String, String> values = new LinkedHashMap<>();
        values.put("ts", ts);
        values.put("id", id);
        values.put("bool", bool);
        values.put("true", yes);
        values.put("false", no);
        values.put("text", text);
        values.put("double", dbl);
        return Collections.unmodifiableMap(values);
    }

    /** The directory name under {@code db/migration}, and Spring Boot's id for the engine. */
    public String vendor() {
        return vendor;
    }

    /** Placeholder name to the SQL it stands for, on this engine. */
    public Map<String, String> placeholders() {
        return placeholders;
    }

    /** The common migrations first, then this engine's own, as the application reads them. */
    public List<String> locations() {
        return List.of(COMMON_LOCATION, "classpath:db/migration/" + vendor);
    }

    /** The dialect for a Spring Boot vendor id, if it is one Vectispire has migrations for. */
    public static Optional<MigrationDialect> ofVendor(String vendor) {
        return Arrays.stream(values()).filter(dialect -> dialect.vendor.equals(vendor)).findFirst();
    }
}

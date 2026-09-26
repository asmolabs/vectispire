package com.asmolabs.vectispire.core.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.io.ClassPathResource;

/**
 * Where a migration may live, and what a migration written once may say (decision 0027).
 *
 * <p><b>Each rule below closes a failure that is silent on at least one engine.</b> Flyway reads
 * {@code common} and then the engine's directory, so a version written for MySQL and PostgreSQL
 * but forgotten for SQLite applies on two engines and is missing on the third without an error; a
 * version in both {@code common} and a vendor directory fails at startup on that vendor only; a
 * file named {@code v40_x.sql} is ignored outright, because Flyway does not validate names it does
 * not recognise. And a type spelled for one engine inside a file every engine runs is the defect
 * decision 0013 was written against — a {@code datetime} there truncates the audit chain's
 * timestamps on MySQL and is a perfectly good type everywhere else.
 *
 * <p>Read from the source tree rather than the classpath: the question is what a commit put in
 * the directories, and a stale build output would answer a different one.
 */
@DisplayName("the migration layout (decision 0027)")
class MigrationLayoutTest {

    private static final Path MIGRATIONS = Path.of("src/main/resources/db/migration");

    /** The integration campaign's probe: a common migration too, so held to the same words. */
    private static final Path PROBE = Path.of("src/integrationTest/resources/db/migration-test/common");

    private static final String COMMON = "common";

    /**
     * The last version written before the rule, in all three vendor directories. They are never
     * moved into {@code common} nor edited to use placeholders, even the thirteen that are
     * identical across engines: Flyway validates the checksum of every applied migration, and a
     * changed file refuses to start every existing installation.
     */
    private static final int LAST_VERSION_BEFORE_THE_RULE = 39;

    private static final Pattern MIGRATION_NAME = Pattern.compile("V([1-9][0-9]*)__[a-z0-9_]+\\.sql");
    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]*)}");

    private static final List<String> VENDORS =
            Arrays.stream(MigrationDialect.values()).map(MigrationDialect::vendor).toList();

    /** A token that belongs to one engine, and what to write instead. */
    private record Forbidden(Pattern pattern, String instead) {
        static Forbidden of(String regex, String instead) {
            return new Forbidden(Pattern.compile(regex, Pattern.CASE_INSENSITIVE), instead);
        }
    }

    private static final List<Forbidden> ENGINE_TOKENS = List.of(
            Forbidden.of("\\bauto_increment\\b|\\bautoincrement\\b|\\bgenerated\\s+(always|by\\s+default)\\b"
                    + "|\\b(big)?serial\\b|\\bidentity\\b", "write `id ${id},`"),
            Forbidden.of("\\bdatetime\\b|\\btimestamptz\\b|\\btimestamp\\b|\\bwith\\s+time\\s+zone\\b",
                    "write ${ts}: a bare datetime truncates to the second on MySQL"),
            Forbidden.of("\\bbit\\s*\\(|\\bb'[01]'|\\bboolean\\b|\\btinyint\\b|\\btrue\\b|\\bfalse\\b",
                    "write ${bool}, ${true} and ${false}"),
            Forbidden.of("\\b(long|medium|tiny)text\\b|\\bclob\\b|\\btext\\b",
                    "write ${text}: MySQL's text stops at 64 KiB"),
            Forbidden.of("\\bdouble\\b|\\bprecision\\b|\\breal\\b|\\bfloat\\b", "write ${double}"),
            Forbidden.of("\\breferences\\b",
                    "a foreign key diverges: MySQL discards an inline one and SQLite cannot add one"
                            + " afterwards — write it in the three vendor directories"),
            Forbidden.of("\\bmodify\\b|\\balter\\s+column\\b|\\bchange\\s+column\\b",
                    "a column change diverges (MODIFY, ALTER COLUMN … TYPE, a table rebuild) — write"
                            + " it in the three vendor directories"),
            Forbidden.of("\\bnow\\s*\\(|\\bcurrent_timestamp\\b|\\binterval\\b|\\bdate_(add|sub)\\b"
                    + "|\\bjulianday\\b|\\bstrftime\\b|\\bextract\\s*\\(",
                    "date arithmetic diverges — write it in the three vendor directories"),
            Forbidden.of("\\bdrop\\s+index\\b|\\bindex\\s+if\\s+not\\s+exists\\b",
                    "index syntax diverges (MySQL's drop index names the table) — write it in the"
                            + " three vendor directories"),
            Forbidden.of("\\bon\\s+conflict\\b|\\bon\\s+duplicate\\s+key\\b|\\binsert\\s+(ignore|or)\\b"
                    + "|\\breplace\\s+into\\b", "an upsert diverges — write it in the three vendor directories"),
            Forbidden.of("\\bpragma\\b|\\bengine\\s*=|\\bunsigned\\b|\\bjsonb?\\b|\\bbytea\\b|\\bblob\\b",
                    "engine-specific — write it in the three vendor directories"),
            Forbidden.of("`|\"|::|\\$",
                    "quoting, casts and dollar bodies are engine-specific — plain identifiers only"));

    private static Map<String, List<String>> filesByDirectory() throws IOException {
        Map<String, List<String>> files = new TreeMap<>();
        try (Stream<Path> directories = Files.list(MIGRATIONS)) {
            for (Path directory : directories.filter(Files::isDirectory).toList()) {
                try (Stream<Path> entries = Files.list(directory)) {
                    files.put(directory.getFileName().toString(),
                            entries.map(entry -> entry.getFileName().toString()).sorted().toList());
                }
            }
        }
        return files;
    }

    private static int version(String file) {
        Matcher name = MIGRATION_NAME.matcher(file);
        return name.matches() ? Integer.parseInt(name.group(1)) : -1;
    }

    private static List<Path> commonMigrations() throws IOException {
        List<Path> files = new ArrayList<>();
        for (Path directory : List.of(MIGRATIONS.resolve(COMMON), PROBE)) {
            try (Stream<Path> entries = Files.list(directory)) {
                entries.filter(entry -> entry.toString().endsWith(".sql")).sorted().forEach(files::add);
            }
        }
        return files;
    }

    /** The statements, without the comments that explain them — a comment may name any engine. */
    private static String statements(String sql) {
        return sql.replaceAll("(?s)/\\*.*?\\*/", " ").replaceAll("--[^\\n]*", " ");
    }

    @Test
    @DisplayName("every directory is an engine Vectispire maps, or common")
    void everyDirectoryIsKnown() throws IOException {
        // A directory called `postgres` or `mariadb` is read by nothing: Spring Boot resolves
        // `{vendor}` to `postgresql`, and there is no MariaDB mapping (decision 0014).
        Set<String> expected = new TreeSet<>(VENDORS);
        expected.add(COMMON);
        assertThat(filesByDirectory().keySet()).containsExactlyInAnyOrderElementsOf(expected);

        try (Stream<Path> entries = Files.list(MIGRATIONS)) {
            assertThat(entries.filter(Files::isRegularFile).map(Path::toString))
                    .as("a file directly under db/migration is on no location Flyway reads")
                    .isEmpty();
        }
    }

    @Test
    @DisplayName("every file is a migration Flyway will read")
    void everyFileIsNamedForFlyway() throws IOException {
        List<String> misnamed = new ArrayList<>();
        filesByDirectory().forEach((directory, files) -> files.stream()
                .filter(file -> version(file) < 0)
                .filter(file -> !(directory.equals(COMMON) && file.equals("README.md")))
                .forEach(file -> misnamed.add(directory + "/" + file)));

        assertThat(misnamed)
                .as("Flyway skips a file whose name it does not recognise, without a word: the"
                        + " migration is simply never applied. Expected V<version>__<description>.sql")
                .isEmpty();
    }

    @Test
    @DisplayName("a version lives in common once, or in every engine's directory — never both, never some")
    void aVersionLivesInOnePlace() throws IOException {
        Map<Integer, Map<String, List<String>>> byVersion = new TreeMap<>();
        filesByDirectory().forEach((directory, files) -> files.stream()
                .filter(file -> version(file) > 0)
                .forEach(file -> byVersion.computeIfAbsent(version(file), v -> new TreeMap<>())
                        .computeIfAbsent(directory, d -> new ArrayList<>())
                        .add(file)));

        List<String> violations = new ArrayList<>();
        byVersion.forEach((version, places) -> {
            places.forEach((directory, files) -> {
                if (files.size() > 1) {
                    violations.add("V" + version + " appears " + files.size() + " times in " + directory
                            + ": " + files);
                }
            });
            if (places.containsKey(COMMON)) {
                if (places.size() > 1) {
                    violations.add("V" + version + " is in common and also in " + without(places, COMMON)
                            + " — Flyway refuses the duplicate on that engine only");
                }
                return;
            }
            Set<String> missing = new TreeSet<>(VENDORS);
            missing.removeAll(places.keySet());
            if (!missing.isEmpty()) {
                violations.add("V" + version + " is in " + places.keySet() + " but not in " + missing
                        + " — it would apply on some engines and silently not on the others");
                return;
            }
            Set<String> names = places.values().stream().flatMap(List::stream).collect(Collectors.toSet());
            if (names.size() > 1) {
                violations.add("V" + version + " has a different name per engine: " + names);
            }
        });

        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("V1 to V39 stay in the vendor directories, where their checksums were recorded")
    void theHistoryStaysWhereItIs() throws IOException {
        Map<String, List<String>> files = filesByDirectory();
        List<String> misplaced = new ArrayList<>();
        for (int version = 1; version <= LAST_VERSION_BEFORE_THE_RULE; version++) {
            int v = version;
            for (String vendor : VENDORS) {
                if (files.get(vendor).stream().noneMatch(file -> version(file) == v)) {
                    misplaced.add("V" + v + " is missing from " + vendor);
                }
            }
        }
        assertThat(misplaced)
                .as("rewriting an applied migration changes its checksum, and Flyway then refuses to"
                        + " start every installation that applied it")
                .isEmpty();
    }

    @Test
    @DisplayName("a new migration identical on every engine is written once, in common")
    void anIdenticalTripleBelongsInCommon() throws IOException {
        // The rule's other half. Three byte-identical copies are the duplication decision 0027
        // exists to end; the next change to them is the one that updates two of the three.
        Map<String, List<String>> files = filesByDirectory();
        List<String> identical = new ArrayList<>();
        for (String file : files.get(VENDORS.getFirst())) {
            if (version(file) <= LAST_VERSION_BEFORE_THE_RULE) {
                continue;
            }
            Set<String> contents = new TreeSet<>();
            for (String vendor : VENDORS) {
                Path copy = MIGRATIONS.resolve(vendor).resolve(file);
                contents.add(Files.exists(copy) ? Files.readString(copy, StandardCharsets.UTF_8) : vendor);
            }
            if (contents.size() == 1) {
                identical.add(file);
            }
        }
        assertThat(identical).isEmpty();
    }

    @Test
    @DisplayName("a common migration names no engine, and only placeholders every engine answers")
    void aCommonMigrationNamesNoEngine() throws IOException {
        Set<String> known = MigrationDialect.MYSQL.placeholders().keySet();
        List<Path> migrations = commonMigrations();
        assertThat(migrations)
                .as("the probe at least must be read, or this passes having looked at nothing")
                .isNotEmpty();

        List<String> violations = new ArrayList<>();
        for (Path migration : migrations) {
            String sql = statements(Files.readString(migration, StandardCharsets.UTF_8));

            Matcher placeholder = PLACEHOLDER.matcher(sql);
            while (placeholder.find()) {
                if (!known.contains(placeholder.group(1))) {
                    violations.add(migration + ": ${" + placeholder.group(1) + "} is not one of " + known);
                }
            }
            if (Pattern.compile("\\$\\{id}\\s+primary\\s+key", Pattern.CASE_INSENSITIVE).matcher(sql).find()) {
                violations.add(migration + ": ${id} already carries `primary key` — write `id ${id},`");
            }

            String bare = PLACEHOLDER.matcher(sql).replaceAll(" ");
            for (Forbidden token : ENGINE_TOKENS) {
                Matcher found = token.pattern().matcher(bare);
                if (found.find()) {
                    violations.add(migration + ": `" + found.group() + "` — " + token.instead());
                }
            }
        }

        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("every engine answers every placeholder, and MySQL keeps the audit chain's precision")
    void everyEngineAnswersEveryPlaceholder() {
        for (MigrationDialect dialect : MigrationDialect.values()) {
            assertThat(dialect.placeholders().keySet())
                    .as("a key one engine lacks fails that engine's startup and no other")
                    .containsExactlyElementsOf(MigrationDialect.MYSQL.placeholders().keySet());
            assertThat(dialect.placeholders().values()).allSatisfy(value -> assertThat(value).isNotBlank());
        }

        // Decision 0013's reason, pinned where the value is: the audit chain hashes a millisecond
        // timestamp, and a bare `datetime` makes it report tampering that never happened.
        assertThat(MigrationDialect.MYSQL.placeholders()).containsEntry("ts", "datetime(6)");
    }

    @Test
    @DisplayName("the application reads common first, then the engine's directory")
    void theApplicationReadsBoth() throws IOException {
        // The unit suite applies `MigrationDialect.locations()`; the application applies this
        // property. If they parted, the tests would apply common migrations production skips.
        var sources = new YamlPropertySourceLoader().load("application", new ClassPathResource("application.yaml"));
        Object locations = sources.getFirst().getProperty("spring.flyway.locations");

        assertThat(String.valueOf(locations).split("\\s*,\\s*"))
                .containsExactly(MigrationDialect.COMMON_LOCATION, "classpath:db/migration/{vendor}");
        assertThat(MigrationDialect.SQLITE.locations())
                .containsExactly(MigrationDialect.COMMON_LOCATION, "classpath:db/migration/sqlite");
    }

    private static Set<String> without(Map<String, ?> places, String excluded) {
        Set<String> rest = new TreeSet<>(places.keySet());
        rest.remove(excluded);
        return rest;
    }
}

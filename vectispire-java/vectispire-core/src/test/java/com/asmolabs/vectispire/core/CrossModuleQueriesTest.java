package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.modulith.ApplicationModule;

/**
 * A query string naming another module's table — the coupling neither Modulith nor ArchUnit can see.
 *
 * <p><b>Why a test of its own.</b> Both read the classes the compiler produced, and a JPQL query is a
 * string in an annotation: {@code select … from ComponentEntity c, ScanEntity s} in {@code inventory}
 * names {@code scanning}'s entity, and no import says so. After step 5 every read of another module's
 * rows went through the owner's API but these, which decision 0029 listed as what was left — and a list
 * in a document is true the day it is written. This reads every {@code @Query} and {@code @NativeQuery}
 * of every repository, resolves each entity name (JPQL), table name (native SQL) and class name (a
 * constructor expression) to the module that owns it, and fails on a reference to another module that
 * {@link #KNOWN} does not carry.
 *
 * <p><b>{@link #KNOWN} only shrinks.</b> Each entry says why the statement crosses — one statement over
 * two tables, cheaper than two queries and a set difference — and {@link #knownReferencesAreStillThere}
 * fails the day its query stops naming the table, so the list cannot outlive the coupling. A new entry is
 * a decision for the review, like a line of a module's allowed dependencies: the owner's API, or a port,
 * is the default answer. An entry pointing against the modules' direction — to a module the origin's
 * {@code package-info} does not list — has to say so ({@link Known#againstTheDirection}), because it is a
 * dependency the graph forbids, hidden in a string.
 *
 * <p>What it cannot see: a query assembled at runtime from strings (there is none — the dynamic reads
 * are Criteria queries over entity classes, which Modulith does see), and an entity spelt otherwise than
 * its name.
 */
@DisplayName("a query names only its own module's tables, or says why")
class CrossModuleQueriesTest {

    private static final String CORE = "com.asmolabs.vectispire.core";

    /** A reference from one repository method's query to a type another module owns. */
    record Reference(String query, String module, String type) {
        @Override
        public String toString() {
            return query + " -> " + module + "." + type;
        }
    }

    /**
     * A reference kept, with its reason. {@code againstTheDirection} when the owner is not among the
     * origin's allowed dependencies: the query reads a module the origin may not use.
     */
    private record Known(Reference reference, boolean againstTheDirection, String reason) {}

    private static final String SCAN_OF_A_COMPONENT = "A component row carries its scan's id, and the target it "
            + "was seen on is the scan's: one join over the whole inventory. Through ScanCatalog it would be "
            + "every scan id of the estate as an in-list, or a scan column copied into t_component.";

    private static final String ORPHAN_SWEEP = "The orphan sweep (OrphanedTargetRows): rows whose target is gone "
            + "are an absence in another module's table, which one `not in (select …)` states; asking "
            + "TargetCatalog for every id and diffing in memory is what the statement avoids. `targets` is "
            + "below, so the direction holds.";

    /**
     * The cross-module statements as step 6 found them — the ones decision 0029 listed, and no other.
     */
    private static final List<Known> KNOWN = List.of(
            new Known(new Reference("AiReviewResults.latestForRepository", "scanning", "ScanEntity"), false,
                    "A review row carries its scan's id, not its repository's: the latest review of a repository "
                            + "is a join to the scans. Through ScanCatalog it would be all the repository's scan "
                            + "ids as an in-list."),
            new Known(new Reference("Components.search", "scanning", "ScanEntity"), false, SCAN_OF_A_COMPONENT),
            new Known(new Reference("Components.versionsOf", "scanning", "ScanEntity"), false, SCAN_OF_A_COMPONENT),
            new Known(new Reference("Components.distinctRepositoriesWithComponents", "scanning", "ScanEntity"), false,
                    SCAN_OF_A_COMPONENT),
            new Known(new Reference("Components.distinctContainersWithComponents", "scanning", "ScanEntity"), false,
                    SCAN_OF_A_COMPONENT),
            new Known(new Reference("Components.distinctPurlsByTarget", "scanning", "ScanEntity"), false,
                    SCAN_OF_A_COMPONENT),
            new Known(new Reference("IssueRepository.findOrphanedIds", "targets", "ContainerEntity"), false, ORPHAN_SWEEP),
            new Known(new Reference("IssueRepository.findOrphanedIds", "targets", "RepositoryEntity"), false, ORPHAN_SWEEP),
            new Known(new Reference("ScanRepository.findOrphanedIds", "targets", "ContainerEntity"), false, ORPHAN_SWEEP),
            new Known(new Reference("ScanRepository.findOrphanedIds", "targets", "RepositoryEntity"), false, ORPHAN_SWEEP),
            new Known(new Reference("ScanRepository.findWithSbomButNoComponents", "inventory", "ComponentEntity"), true,
                    "The inventory's backfill (InventoryBackfill, through ScanCatalog) selects the scans whose SBOM "
                            + "has no component row yet, by the absence of rows so that the query and the table "
                            + "cannot disagree. It reads `inventory` from `scanning`, which may not use it: the "
                            + "statement belongs in `inventory`, over its own table, asking ScanCatalog for the "
                            + "scans that hold an SBOM."));

    private static JavaClasses classes;

    @BeforeAll
    static void importClasses() {
        classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages(CORE);
    }

    private static String moduleOf(String packageName) {
        String rest = packageName.substring(CORE.length() + 1);
        return rest.contains(".") ? rest.substring(0, rest.indexOf('.')) : rest;
    }

    private record Owned(String module, String type) {}

    /** Every reference a repository's query makes to a type another module owns. */
    private static Set<Reference> crossModuleReferences() {
        Map<String, Owned> byEntityName = new HashMap<>();
        Map<String, Owned> byTable = new HashMap<>();
        for (JavaClass type : classes) {
            if (!type.isAnnotatedWith(Entity.class)) {
                continue;
            }
            Owned owned = new Owned(moduleOf(type.getPackageName()), type.getSimpleName());
            String name = type.getAnnotationOfType(Entity.class).name();
            byEntityName.put(name.isEmpty() ? type.getSimpleName() : name, owned);
            if (type.isAnnotatedWith(Table.class)) {
                byTable.put(type.getAnnotationOfType(Table.class).name().toLowerCase(Locale.ROOT), owned);
            }
        }
        // A wrong import would find nothing and pass: the failure mode of a rule that reads strings.
        assertThat(byEntityName).as("entities found").hasSizeGreaterThan(30);
        assertThat(byTable).as("tables found").hasSameSizeAs(byEntityName);

        Set<Reference> references = new TreeSet<>(Comparator.comparing(Reference::toString));
        int read = 0;
        for (JavaClass type : classes) {
            if (!type.isAssignableTo(Repository.class) || !type.getPackageName().startsWith(CORE + ".")) {
                continue;
            }
            String module = moduleOf(type.getPackageName());
            for (JavaMethod method : type.getMethods()) {
                List<String> jpql = new ArrayList<>();
                List<String> sql = new ArrayList<>();
                if (method.isAnnotatedWith(Query.class)) {
                    Query query = method.getAnnotationOfType(Query.class);
                    List<String> into = query.nativeQuery() ? sql : jpql;
                    into.add(query.value());
                    if (!query.countQuery().isEmpty()) {
                        into.add(query.countQuery());
                    }
                }
                if (method.isAnnotatedWith(NativeQuery.class)) {
                    sql.add(method.getAnnotationOfType(NativeQuery.class).value());
                }
                read += jpql.size() + sql.size();
                String where = type.getSimpleName() + "." + method.getName();
                for (String text : jpql) {
                    byEntityName.forEach((name, owned) -> {
                        if (!owned.module().equals(module) && names(text, name, false)) {
                            references.add(new Reference(where, owned.module(), owned.type()));
                        }
                    });
                    // A constructor expression, or any class spelt in full: a projection of another module
                    // is a coupling of the same kind as its entity.
                    Matcher qualified = Pattern.compile(Pattern.quote(CORE) + "\\.([a-z]+)\\.([\\w.$]+)").matcher(text);
                    while (qualified.find()) {
                        if (!qualified.group(1).equals(module)) {
                            String simple = qualified.group(2).substring(qualified.group(2).lastIndexOf('.') + 1);
                            references.add(new Reference(where, qualified.group(1), simple));
                        }
                    }
                }
                for (String text : sql) {
                    byTable.forEach((table, owned) -> {
                        if (!owned.module().equals(module) && names(text, table, true)) {
                            references.add(new Reference(where, owned.module(), owned.type()));
                        }
                    });
                }
            }
        }
        assertThat(read).as("query annotations read").isGreaterThan(100);
        return references;
    }

    /**
     * Whether {@code text} names {@code name} as a word: not inside a longer identifier, and not as a
     * path segment ({@code i.scan}) or a parameter ({@code :scan}).
     */
    private static boolean names(String text, String name, boolean ignoringCase) {
        return Pattern.compile("(?<![\\w.:$])" + Pattern.quote(name) + "(?![\\w$])",
                ignoringCase ? Pattern.CASE_INSENSITIVE : 0).matcher(text).find();
    }

    @Test
    @DisplayName("names another module's table only where the list says why")
    void noUnlistedCrossModuleReference() {
        Set<Reference> known = KNOWN.stream().map(Known::reference).collect(Collectors.toSet());
        assertThat(crossModuleReferences().stream().filter(reference -> !known.contains(reference)).toList())
                .as("queries naming another module's table: ask the owner's API instead, or add the entry to "
                        + "KNOWN with its reason, in the review that decides it")
                .isEmpty();
    }

    @Test
    @DisplayName("a listed reference is still made, or it leaves the list")
    void knownReferencesAreStillThere() {
        Set<Reference> found = crossModuleReferences();
        assertThat(KNOWN.stream().map(Known::reference).filter(reference -> !found.contains(reference)).toList())
                .as("listed in KNOWN but no longer in any query: remove them")
                .isEmpty();
        assertThat(KNOWN).as("every entry says why").allSatisfy(entry -> assertThat(entry.reason()).isNotBlank());
    }

    @Test
    @DisplayName("a listed reference against the modules' direction says so")
    void referencesAgainstTheDirectionAreNamed() throws ClassNotFoundException {
        // The reference is a dependency in all but the compiler's eyes. Where the origin's package-info
        // allows the owner, the string only hides an edge the graph has; where it does not, it hides one
        // the graph forbids, and the entry must carry the flag so that nobody reads it as the first kind.
        for (Known entry : KNOWN) {
            String origin = classes.stream()
                    .filter(type -> type.getSimpleName().equals(entry.reference().query().split("\\.")[0])
                            && type.isAssignableTo(Repository.class))
                    .map(type -> moduleOf(type.getPackageName()))
                    .findFirst().orElseThrow();
            List<String> allowed = Arrays.stream(Class.forName(CORE + "." + origin + ".package-info")
                            .getAnnotation(ApplicationModule.class).allowedDependencies())
                    .map(dependency -> dependency.split("::")[0])
                    .toList();
            assertThat(!allowed.contains(entry.reference().module()))
                    .as("%s: %s may %suse %s", entry.reference(), origin,
                            allowed.contains(entry.reference().module()) ? "" : "not ", entry.reference().module())
                    .isEqualTo(entry.againstTheDirection());
        }
    }
}

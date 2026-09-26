package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.modulith.core.ApplicationModule;
import org.springframework.modulith.core.ApplicationModules;
import org.springframework.modulith.core.Violations;
import org.springframework.modulith.docs.Documenter;

/**
 * What Spring Modulith sees in the control plane, written down — <b>observed, not enforced</b>.
 *
 * <p><b>Why observation only.</b> Modulith takes the packages directly under the application class
 * as its modules. Since steps 3 and 4 (decision 0028) nineteen of them are domains — the foundation
 * and the leaf and middle domains, each {@code core.<domain>} with {@code web}, {@code internal} and
 * {@code persistence} beneath it — and five are still the layers of the old packaging: {@code api},
 * {@code services}, {@code repositories}, {@code persistence}, {@code config}. {@code issues},
 * {@code scanning}, {@code targets}, {@code platform} and {@code shared} are sub-packages of {@code
 * services}, so to Modulith they are one module's internals, and every module that calls one of them
 * is reported as reaching into {@code services}; every module they call closes a cycle through it.
 * Those violations are true of the packaging and are step 5's to remove, so this test builds the
 * model, writes the report and the generated documentation, prints what {@code verify()} would
 * reject, and fails on none of it. What it does assert is that the model was built, that it sees the
 * modules the migration has made, and that the files exist — an observation that silently produced
 * nothing would read exactly like an observation that found nothing.
 *
 * <p><b>Step 6 of the migration turns it into {@code verify()}</b>, once step 5 has moved {@code
 * issues}, {@code scanning} and {@code targets} into modules of their own and dissolved {@code
 * platform} and {@code shared}, so that every violation means a domain reached into another.
 *
 * <p>The output lands in {@code build/modulith-docs/}: {@code modules.txt} (the module model and
 * the violations), {@code components.puml} and one {@code module-*.puml} per module (C4 component
 * diagrams in PlantUML), {@code module-*.adoc} (the module canvases) and {@code all-docs.adoc}.
 * Summarised in {@code docs/architecture/en/05-modularity.md}.
 */
@DisplayName("modularity as Spring Modulith sees it (observation only)")
class ModularityObservationTest {

    /** Relative to the module directory, which is where Gradle runs a test. */
    private static final Path OUTPUT = Path.of("build", "modulith-docs");

    private static final Pattern NON_EXPOSED =
            Pattern.compile("Module '([^']+)' depends on non-exposed type (\\S+) within module '([^']+)'");

    /** The top-level packages of the layered packaging, which step 5 empties. */
    private static final Set<String> LAYERED = Set.of("api", "services", "repositories", "persistence", "config");

    /** The domains steps 3 and 4 made modules — the same list as {@code ArchitectureTest.MODULES}. */
    private static final List<String> MODULES = List.of(
            "settings", "outbound", "crypto", "audit", "outbox", "reporting",
            "siem", "rules", "ai", "threatintel", "tickets", "agents", "notifications", "exports", "gate",
            "inventory", "posture", "compliance", "access");

    /**
     * What {@code verify()} reported before step 3, taken on 2026-09-26 (step 2): five layer modules and
     * one kind of message, {@code api} reaching the non-exposed service sub-packages. Kept here so the
     * report states the comparison it exists for.
     */
    private static final String BASELINE = "1304 messages, one kind: api -> non-exposed types of services "
            + "(208 distinct types); 5 modules, all layers";

    private static ApplicationModules modules;
    private static Violations violations;

    @BeforeAll
    static void observe() throws IOException {
        modules = ApplicationModules.of(VectispireApplication.class);
        violations = modules.detectViolations();

        new Documenter(modules, Documenter.Options.defaults().withOutputFolder(OUTPUT.toString()))
                .writeDocumentation();

        StringBuilder report = new StringBuilder();
        report.append("# Spring Modulith observation of ").append(VectispireApplication.class.getName()).append("\n\n");
        report.append("## Modules (").append(modules.stream().count()).append(")\n\n");
        modules.forEach(module -> report.append("- ").append(summary(module)).append('\n'));
        report.append("\n## Violations verify() would report (").append(violations.getMessages().size()).append(")\n\n");
        // One message per offending dependency — a constructor, a field, each call — so the count
        // measures lines of code more than it measures problems. Grouped first by the edge and the
        // number of distinct types it reaches, which is the figure worth comparing between steps.
        Map<String, Set<String>> byEdge = new TreeMap<>();
        Map<String, Integer> messagesByEdge = new TreeMap<>();
        for (String message : violations.getMessages()) {
            Matcher nonExposed = NON_EXPOSED.matcher(message);
            boolean matched = nonExposed.find();
            String edge = matched
                    ? nonExposed.group(1) + " -> non-exposed types of " + nonExposed.group(3)
                    : "other: " + message.lines().findFirst().orElse("");
            byEdge.computeIfAbsent(edge, ignored -> new TreeSet<>()).add(matched ? nonExposed.group(2) : message);
            messagesByEdge.merge(edge, 1, Integer::sum);
        }
        report.append("### By kind\n\n");
        report.append("Before step 3 (baseline): ").append(BASELINE).append("\n\n");
        Map<String, Integer> byKind = new TreeMap<>();
        for (String message : violations.getMessages()) {
            byKind.merge(kindOf(message), 1, Integer::sum);
        }
        byKind.forEach((kind, count) -> report.append("- ").append(kind).append(": ").append(count).append('\n'));
        report.append("\n### By edge\n\n");
        byEdge.forEach((edge, types) -> report.append("- ").append(edge).append(": ")
                .append(messagesByEdge.get(edge)).append(" messages, ").append(types.size())
                .append(" distinct types\n"));
        report.append("\n### Every message\n\n");
        violations.getMessages().forEach(message -> report.append("- ").append(message.replace('\n', ' ')).append('\n'));
        report.append("\n## Module model\n\n").append(modules).append('\n');
        Files.writeString(OUTPUT.resolve("modules.txt"), report);

        // Printed as well, so a CI log carries the observation without an artefact download.
        System.out.println(report);
    }

    /**
     * The kind of a message, as the migration reads it: a reach into a package of the layered
     * packaging is step 5's to remove, a reach into a module is a domain crossing another's boundary,
     * and a cycle is named with the module it starts from.
     */
    private static String kindOf(String message) {
        Matcher nonExposed = NON_EXPOSED.matcher(message);
        if (nonExposed.find()) {
            boolean fromLayered = LAYERED.contains(nonExposed.group(1));
            boolean intoLayered = LAYERED.contains(nonExposed.group(3));
            return "non-exposed type, " + (fromLayered ? "layered package" : "module") + " -> "
                    + (intoLayered ? "layered package (step 5)" : "module");
        }
        if (message.startsWith("Cycle detected")) {
            return "cycle";
        }
        return "other";
    }

    private static String summary(ApplicationModule module) {
        List<String> dependsOn = module.getDirectDependencies(modules).uniqueModules()
                .map(ApplicationModule::getIdentifier)
                .map(Object::toString)
                .sorted()
                .toList();
        return module.getIdentifier() + " (" + module.getBasePackage().getName() + ") -> " + dependsOn;
    }

    @Test
    @DisplayName("detects the application's top-level packages as modules: the domains moved so far, and the layers left")
    void detectsModules() {
        // Every domain steps 3 and 4 moved is a module, and the layers step 5 empties are still there:
        // the day one of these disappears, the packaging changed and this list — with the report — says
        // by how much.
        assertThat(modules.stream().map(module -> module.getIdentifier().toString()))
                .containsAll(MODULES)
                .containsAll(LAYERED)
                .hasSize(MODULES.size() + LAYERED.size());
    }

    @Test
    @DisplayName("sees the foundation as shared modules")
    void seesTheFoundationAsShared() {
        // Declared on the application class; a module missing from that list would still be used by
        // every domain, and a module test would boot without it.
        assertThat(modules.getSharedModules().stream().map(module -> module.getIdentifier().toString()))
                .containsExactlyInAnyOrder("settings", "outbound", "crypto", "audit", "outbox", "reporting");
    }

    @Test
    @DisplayName("writes its report, its component diagrams and its module canvases")
    void writesTheDocumentation() throws IOException {
        assertThat(OUTPUT.resolve("modules.txt")).isNotEmptyFile();
        assertThat(OUTPUT.resolve("components.puml")).isNotEmptyFile();
        try (Stream<Path> files = Files.list(OUTPUT)) {
            List<String> names = files.map(path -> path.getFileName().toString()).toList();
            assertThat(names).as("one component diagram per module")
                    .filteredOn(name -> name.startsWith("module-") && name.endsWith(".puml"))
                    .hasSameSizeAs(modules.stream().toList());
            assertThat(names).as("one canvas per module")
                    .filteredOn(name -> name.startsWith("module-") && name.endsWith(".adoc"))
                    .hasSameSizeAs(modules.stream().toList());
        }
    }
}

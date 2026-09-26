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
 * as its modules. Since step 5 (decisions 0028 and 0029) every one of them is a domain — {@code
 * core.<domain>} with {@code web}, {@code internal} and {@code persistence} beneath it — but {@code
 * config}, the application's infrastructure; the layers of the old packaging ({@code api}, {@code
 * services}, {@code repositories}, {@code persistence}) are gone, and with them every violation this
 * report used to list: it finds none. It still builds the model, writes the report and the generated
 * documentation, prints what {@code verify()} would reject, and fails on none of it, because turning
 * it into a gate is step 6's decision, not a side effect of this one. What it does assert is that the
 * model was built, that it sees the modules the migration has made, and that the files exist — an
 * observation that silently produced nothing would read exactly like an observation that found
 * nothing.
 *
 * <p><b>Step 6 of the migration turns it into {@code verify()}</b>, so that a violation fails the
 * build: every message would now mean a domain reached into another.
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

    /**
     * The top-level packages that are no domain's. The four layers of the old packaging were in this
     * set until step 5 emptied them; {@code config} is what is left.
     */
    private static final Set<String> LAYERED = Set.of("config");

    /** The domains steps 3 to 5 made modules — the same list as {@code ArchitectureTest.MODULES}. */
    private static final List<String> MODULES = List.of(
            "settings", "outbound", "crypto", "audit", "outbox", "reporting",
            "siem", "rules", "ai", "threatintel", "tickets", "agents", "notifications", "exports", "gate",
            "inventory", "posture", "compliance", "access",
            "targets", "scanning", "issues", "maintenance", "platform");

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
     * The kind of a message, as the migration reads it: a reach into {@code config} — the layered
     * packaging's last package, which step 5 left — is infrastructure, a reach into a module is a
     * domain crossing another's boundary, and a cycle is named with the module it starts from.
     */
    private static String kindOf(String message) {
        Matcher nonExposed = NON_EXPOSED.matcher(message);
        if (nonExposed.find()) {
            boolean fromLayered = LAYERED.contains(nonExposed.group(1));
            boolean intoLayered = LAYERED.contains(nonExposed.group(3));
            return "non-exposed type, " + (fromLayered ? "config" : "module") + " -> "
                    + (intoLayered ? "config" : "module");
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
        // Every domain is a module, and `config` is the one package that is not: the day one of these
        // disappears, or a new top-level package appears, the packaging changed and this list — with
        // the report — says by how much.
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
                .containsExactlyInAnyOrder("settings", "outbound", "crypto", "audit", "outbox", "reporting", "maintenance");
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

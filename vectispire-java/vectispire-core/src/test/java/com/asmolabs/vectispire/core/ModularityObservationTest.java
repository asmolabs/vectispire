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
 * as its modules. This code is packaged by layer, so it sees {@code api}, {@code services},
 * {@code repositories}, {@code persistence}, {@code config}… as modules — the layers {@code
 * ArchitectureTest} already checks — and not the domains decision 0026 draws inside {@code
 * services}. A module's sub-packages are its internals to Modulith, and every service lives in a
 * sub-package of {@code services}: its verification reports each controller's use of a service as a
 * violation — true of the packaging, useless as a gate. So
 * this test builds the model, writes the report and the generated documentation, prints what
 * {@code verify()} would reject, and fails on none of it. What it does assert is that the model was
 * built and the files exist — an observation that silently produced nothing would read exactly like
 * an observation that found nothing.
 *
 * <p><b>Step 6 of the migration turns it into {@code verify()}</b>, once steps 3 to 5 have packaged
 * the code by domain — {@code issues/api}, {@code issues/services}, {@code issues/persistence} — so
 * that Modulith's modules are the domains and a violation means a domain reached into another.
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

    private static String summary(ApplicationModule module) {
        List<String> dependsOn = module.getDirectDependencies(modules).uniqueModules()
                .map(ApplicationModule::getIdentifier)
                .map(Object::toString)
                .sorted()
                .toList();
        return module.getIdentifier() + " (" + module.getBasePackage().getName() + ") -> " + dependsOn;
    }

    @Test
    @DisplayName("detects the application's top-level packages as modules")
    void detectsModules() {
        // The expected finding, and the reason for steps 3 to 5: packaged by layer, the modules are
        // the layers. When this list becomes the domains, the packaging has changed.
        assertThat(modules.stream().map(module -> module.getIdentifier().toString()))
                .contains("api", "services", "repositories", "persistence", "config");
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

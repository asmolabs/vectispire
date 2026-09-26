package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.modulith.core.ApplicationModule;
import org.springframework.modulith.core.ApplicationModules;
import org.springframework.modulith.docs.Documenter;

/**
 * The module boundaries, verified by Spring Modulith — <b>the build fails on any violation</b>
 * (decision 0030).
 *
 * <p>{@link ApplicationModules#verify()} is the authority for what crosses between modules: that the
 * modules form no cycle, and that a module reaches another only through its root package or a named
 * interface ({@code @NamedInterface} on a {@code package-info}). Step 5 left nothing for it to report
 * (decision 0029); from here on a message is a reach somebody just added, and the build says so.
 *
 * <p>It also writes what it sees to {@code build/modulith-docs/}: {@code modules.txt} (the module
 * model), {@code components.puml} and one {@code module-*.puml} per module (C4 component diagrams in
 * PlantUML), {@code module-*.adoc} (the module canvases) and {@code all-docs.adoc}. Summarised in
 * {@code docs/architecture/en/05-modularity.md}.
 */
@DisplayName("the module boundaries, as Spring Modulith verifies them")
class ModularityTest {

    /** Relative to the module directory, which is where Gradle runs a test. */
    private static final Path OUTPUT = Path.of("build", "modulith-docs");

    /**
     * The top-level packages that are no domain's: {@code config}, the datasource and the engines'
     * setup.
     */
    private static final Set<String> OUTSIDE_MODULES = Set.of("config");

    /** The domains — the same list as {@code ArchitectureTest.MODULES}. */
    private static final List<String> MODULES = List.of(
            "settings", "outbound", "crypto", "audit", "outbox", "reporting",
            "siem", "rules", "ai", "threatintel", "tickets", "agents", "notifications", "exports", "gate",
            "inventory", "posture", "compliance", "access",
            "targets", "scanning", "issues", "maintenance", "platform");

    private static ApplicationModules modules;

    @BeforeAll
    static void model() throws IOException {
        modules = ApplicationModules.of(VectispireApplication.class);

        new Documenter(modules, Documenter.Options.defaults().withOutputFolder(OUTPUT.toString()))
                .writeDocumentation();

        StringBuilder report = new StringBuilder();
        report.append("# Spring Modulith model of ").append(VectispireApplication.class.getName()).append("\n\n");
        report.append("## Modules (").append(modules.stream().count()).append(")\n\n");
        modules.forEach(module -> report.append("- ").append(summary(module)).append('\n'));
        report.append("\n## Module model\n\n").append(modules).append('\n');
        Files.createDirectories(OUTPUT);
        Files.writeString(OUTPUT.resolve("modules.txt"), report);
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
    @DisplayName("reports no violation: no cycle, no reach into another module's internals")
    void verifies() {
        // Throws with every message: the edge and the type reached. The answer is the owner's API or a
        // port; never a class moved to wherever the message stops.
        modules.verify();
    }

    @Test
    @DisplayName("detects every domain and config as modules, and nothing else")
    void detectsModules() {
        // A module Modulith does not see is a module nothing verifies: a misspelt package, or a new
        // top-level package nobody placed. The list and ArchitectureTest's move together.
        assertThat(modules.stream().map(module -> module.getIdentifier().toString()))
                .containsAll(MODULES)
                .containsAll(OUTSIDE_MODULES)
                .hasSize(MODULES.size() + OUTSIDE_MODULES.size());
    }

    @Test
    @DisplayName("sees the foundation as shared modules")
    void seesTheFoundationAsShared() {
        // Declared on the application class. A shared module is an allowed dependency of every module
        // without being listed; one missing here would fail `verifies` in every module that uses it.
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

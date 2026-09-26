package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.assertj.core.api.SoftAssertions;
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
 * modules form no cycle, that a module reaches another only through its root package or a named
 * interface ({@code @NamedInterface} on a {@code package-info}), and that it uses only the modules and
 * named interfaces its own {@code package-info} lists in {@code @ApplicationModule(allowedDependencies =
 * …)}. Those were three ArchUnit rules and a table in {@code ArchitectureTest} until step 6 of the
 * migration; what Modulith cannot express stayed there — the layers inside a module, and the service
 * layers that may not use {@code access} although their routes do. The edges between the shared
 * foundation modules, which Modulith allows wholesale, are held here, by {@link
 * #eachModuleDeclaresExactlyWhatItUses}.
 *
 * <p><b>It fails on nothing it was not asked.</b> Modulith reads the classes the compiler produced, not
 * the strings in them: a JPQL query naming another module's entity is invisible to it, which is {@code
 * CrossModuleQueriesTest}'s business. And a module whose {@code package-info} declares no list is open
 * to every module — which is why {@link #everyModuleButThePlatformDeclaresWhatItMayUse} fails on one.
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

    private static final String CORE = "com.asmolabs.vectispire.core";

    /**
     * The top-level packages that are no domain's: {@code config}, the datasource and the engines'
     * setup. It declares no list either, and needs none — nothing lists it, so nothing may use it.
     */
    private static final Set<String> OUTSIDE_MODULES = Set.of("config");

    /** The domains — the same list as {@code ArchitectureTest.MODULES}. */
    private static final List<String> MODULES = List.of(
            "settings", "outbound", "crypto", "audit", "outbox", "reporting",
            "siem", "rules", "ai", "threatintel", "tickets", "agents", "notifications", "exports", "gate",
            "inventory", "posture", "compliance", "access",
            "targets", "scanning", "issues", "maintenance", "platform");

    /**
     * The one module that may use any other, and so the one that declares no list: the shell (decision
     * 0029).
     */
    private static final String PLATFORM = "platform";

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
        return module.getIdentifier() + " (" + module.getBasePackage().getName() + ") -> " + dependsOn
                + ", allowed: " + module.getAllowedDependencies(modules);
    }

    @Test
    @DisplayName("reports no violation: no cycle, no reach into another module's internals, no undeclared dependency")
    void verifies() {
        // Throws with every message: the edge, the type reached and the list it is missing from. The
        // answer is the owner's API, a port, or — decided in the review, with its reason — a line in the
        // origin's `package-info`; never a class moved to wherever the message stops.
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
    @DisplayName("every module but the platform declares what it may use")
    void everyModuleButThePlatformDeclaresWhatItMayUse() throws ClassNotFoundException {
        // To Modulith a module with no `allowedDependencies` may use every other module's API — the
        // default is open, not empty. A `package-info` losing its list, or a new module created without
        // one, would therefore turn the table off for that module without a message. `platform` is the
        // one module that may use any other, and says so by declaring nothing.
        for (String module : MODULES) {
            org.springframework.modulith.ApplicationModule declared =
                    Class.forName(CORE + "." + module + ".package-info")
                            .getAnnotation(org.springframework.modulith.ApplicationModule.class);
            assertThat(declared).as("%s's package-info carries @ApplicationModule", module).isNotNull();
            boolean open = Arrays.equals(declared.allowedDependencies(),
                    new String[] {org.springframework.modulith.ApplicationModule.OPEN_TOKEN});
            assertThat(open)
                    .as(module.equals(PLATFORM)
                            ? "platform may use any module, and declares no list"
                            : module + " declares the modules it may use in its package-info")
                    .isEqualTo(module.equals(PLATFORM));
        }
    }

    @Test
    @DisplayName("a module declares exactly what it uses")
    void eachModuleDeclaresExactlyWhatItUses() throws ClassNotFoundException {
        // Two halves. **Nothing left over**: the lists are the code as it stands, not a budget (decision
        // 0026's table was the same) — a line left behind when its last use went is a dependency the next
        // change can take without a review noticing; `verifies` only fails on a use the list lacks.
        // **Nothing missing between the foundation modules**: Modulith adds every shared module to every
        // module's allowed dependencies, the foundation's own included, so `verifies` would let `settings`
        // use `audit`. A foundation module's list names the foundation modules it uses, and this is where
        // that list is held to the code.
        SoftAssertions softly = new SoftAssertions();
        for (String name : MODULES) {
            if (name.equals(PLATFORM)) {
                continue;
            }
            ApplicationModule module = modules.getModuleByName(name).orElseThrow();
            // A domain does not list the foundation, which is shared; a foundation module lists the other
            // foundation modules it uses, since sharing says nothing about the edges between them.
            boolean foundation = modules.getSharedModules().contains(module);
            Set<String> used = module.getDirectDependencies(modules).stream()
                    .filter(dependency -> foundation
                            || !modules.getSharedModules().contains(dependency.getTargetModule()))
                    .map(dependency -> {
                        ApplicationModule target = dependency.getTargetModule();
                        return target.getNamedInterfaces().getNamedInterfacesContaining(dependency.getTargetType())
                                .filter(org.springframework.modulith.core.NamedInterface::isNamed)
                                .map(named -> target.getIdentifier() + "::" + named.getName())
                                .findFirst()
                                .orElse(target.getIdentifier().toString());
                    })
                    .collect(Collectors.toCollection(TreeSet::new));
            List<String> declared = Arrays.asList(Class.forName(CORE + "." + name + ".package-info")
                    .getAnnotation(org.springframework.modulith.ApplicationModule.class).allowedDependencies());
            softly.assertThat(used).as("what %s uses, against what its package-info declares", name)
                    .containsExactlyInAnyOrderElementsOf(declared);
        }
        softly.assertAll();
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

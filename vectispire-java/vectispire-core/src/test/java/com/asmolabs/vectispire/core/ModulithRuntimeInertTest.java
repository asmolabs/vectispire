package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Spring Modulith verifies the build and does nothing at runtime.
 *
 * <p><b>Two claims, checked where each can fail.</b> The production jar carries Modulith's annotations
 * and nothing else (decision 0030): the core starter used to put its runtime model, its "moments" — an
 * hourly event on a scheduler of its own, a Jackson module in the web layer's mapper — and ArchUnit on
 * the main classpath, and kept the moments off with two auto-configuration exclusions. Taking the
 * annotations alone made the exclusions pointless and the claim structural; {@link
 * #shipsOnlyTheAnnotations} reads the resolved production classpath from the lockfile, so a starter
 * added back to {@code implementation} fails here and not in an incident. The context below runs on the
 * <em>test</em> classpath, which carries Modulith's core for {@code ModularityTest}: that nothing of it
 * activates there either is {@link #contributesNothing}'s. The build keeps the outbox as the one event
 * registry (decision 0025); a Modulith bean appearing means an auto-configuration became active, and it
 * should be decided, not discovered.
 */
@DisplayName("Spring Modulith at runtime")
class ModulithRuntimeInertTest extends VectispireContextTest {

    /**
     * The one Modulith bean allowed on the test classpath: a check that refuses to start when an {@code
     * ApplicationModuleInitializer} exists without the runtime artifact. It comes with Modulith's core,
     * which production does not carry, and registers and runs nothing when there is no initializer.
     */
    private static final List<String> ALLOWED =
            List.of("org.springframework.modulith.core.config.ApplicationModuleInitializerRuntimeVerification");

    /** What production may carry of Modulith: its annotations, and the BOM that versions them. */
    private static final List<String> SHIPPED = List.of(
            "org.springframework.modulith:spring-modulith-api", "org.springframework.modulith:spring-modulith-bom");

    /** Relative to the module directory, which is where Gradle runs a test. */
    private static final Path LOCKFILE = Path.of("gradle.lockfile");

    @Autowired
    private ConfigurableApplicationContext context;

    @Test
    @DisplayName("contributes no bean beyond the check that its runtime is absent")
    void contributesNothing() {
        ConfigurableListableBeanFactory beans = context.getBeanFactory();
        List<String> modulith = Arrays.stream(beans.getBeanDefinitionNames())
                .map(name -> {
                    Class<?> type = beans.getType(name, false);
                    return type == null ? beans.getBeanDefinition(name).getBeanClassName() : type.getName();
                })
                .filter(Objects::nonNull)
                .filter(type -> type.startsWith("org.springframework.modulith."))
                .filter(type -> !ALLOWED.contains(type))
                .toList();

        assertThat(modulith).as("Modulith beans active in the application").isEmpty();
    }

    @Test
    @DisplayName("ships its annotations and nothing else: no runtime, no moments, no ArchUnit")
    void shipsOnlyTheAnnotations() throws IOException {
        // `productionRuntimeClasspath` is what `bootJar` packs. The lockfile is written from the resolved
        // graph and the build refuses to run when the two differ, so reading it is reading the jar's
        // contents — without building the jar in a unit test.
        List<String> production = Files.readAllLines(LOCKFILE).stream()
                // `group:artifact:version=configurations`; the `empty=` line names no artifact.
                .filter(line -> line.indexOf(':') > 0 && line.indexOf(':') < line.indexOf('='))
                .filter(line -> Arrays.asList(line.substring(line.indexOf('=') + 1).split(","))
                        .contains("productionRuntimeClasspath"))
                .map(line -> line.substring(0, line.lastIndexOf(':', line.indexOf('='))))
                .toList();
        assertThat(production).as("the production classpath was read at all")
                .contains("org.springframework:spring-webmvc");
        assertThat(production).as("Modulith artifacts in the production jar")
                .filteredOn(artifact -> artifact.startsWith("org.springframework.modulith:"))
                .containsExactlyInAnyOrderElementsOf(SHIPPED);
        assertThat(production).as("ArchUnit in the production jar")
                .noneMatch(artifact -> artifact.startsWith("com.tngtech.archunit:"));
    }
}

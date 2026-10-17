package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.modulith.core.ApplicationModule;
import org.springframework.modulith.core.ApplicationModules;
import org.springframework.modulith.core.NamedInterface;

/**
 * The module model as Spring Modulith reads it — the Rust control plane's {@code cp-arch-tests} holds its {@code
 * data/edges.toml} to it ({@code vectispire-rust/reference/modules/modules.json}).
 *
 * <p>{@code edges.toml} was written by hand from the {@code package-info} files, and nothing compared the two after
 * that: a line added on one side only would have left the Rust rules enforcing a graph Java no longer has. So the
 * answers here are Modulith's own — the shared modules {@code @Modulithic} declares, as {@code ApplicationModules}
 * resolves them, and each module's named interfaces as it detects them — and each module's {@code
 * allowedDependencies} as its annotation carries it, which is what {@code verify()} enforces. Nothing is restated.
 */
class ModulesReferenceSetTest {

    private static final String CORE = "com.asmolabs.vectispire.core";

    @Test
    void theModuleModel() throws ClassNotFoundException {
        ApplicationModules modules = ApplicationModules.of(VectispireApplication.class);
        ObjectNode out = RustReference.object();

        ArrayNode shared = out.putArray("shared");
        modules.getSharedModules().stream()
                .map(module -> module.getIdentifier().toString())
                .sorted()
                .forEach(shared::add);

        ArrayNode listed = out.putArray("modules");
        List<ApplicationModule> sorted = modules.stream()
                .filter(module -> !ArchitectureTest.OUTSIDE_MODULES.contains(module.getIdentifier().toString()))
                .sorted(java.util.Comparator.comparing(module -> module.getIdentifier().toString()))
                .toList();
        // Every domain, and nothing else: a module missing here would be one the Rust side never compares.
        assertThat(sorted).extracting(module -> module.getIdentifier().toString())
                .containsExactlyInAnyOrderElementsOf(ArchitectureTest.MODULES);
        for (ApplicationModule module : sorted) {
            String name = module.getIdentifier().toString();
            String[] declared = Class.forName(CORE + "." + name + ".package-info")
                    .getAnnotation(org.springframework.modulith.ApplicationModule.class)
                    .allowedDependencies();
            boolean open = Arrays.equals(declared,
                    new String[] {org.springframework.modulith.ApplicationModule.OPEN_TOKEN});
            ObjectNode row = listed.addObject();
            row.put("name", name);
            row.put("open", open);
            ArrayNode allowed = row.putArray("allowed");
            if (!open) {
                Arrays.stream(declared).sorted().forEach(allowed::add);
            }
            ArrayNode interfaces = row.putArray("interfaces");
            module.getNamedInterfaces().stream()
                    .filter(NamedInterface::isNamed)
                    .map(NamedInterface::getName)
                    .sorted()
                    .forEach(interfaces::add);
        }
        RustReference.expect("modules/modules.json", out, ModulesReferenceSetTest.class);
    }
}

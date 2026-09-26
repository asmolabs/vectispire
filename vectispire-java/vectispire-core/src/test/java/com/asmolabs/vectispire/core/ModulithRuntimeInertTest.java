package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Spring Modulith is on the classpath and does nothing at runtime.
 *
 * <p><b>Observation mode is a claim about production, so it is checked on the application.</b> The
 * core starter auto-configures "moments" unless told otherwise — an hourly event on a scheduler of
 * its own, and a Jackson module in the web layer's mapper — and a later Modulith version may add
 * more. Nothing of it was asked for: the build keeps the outbox as the one event registry (decision
 * 0025) and uses Modulith only from {@code ModularityObservationTest}. A bean from Modulith's
 * packages appearing here means an auto-configuration became active, and it should be decided, not
 * discovered.
 */
@DisplayName("Spring Modulith at runtime")
class ModulithRuntimeInertTest extends VectispireContextTest {

    /**
     * The one Modulith bean allowed: a check that refuses to start when an {@code
     * ApplicationModuleInitializer} exists without the runtime artifact. It registers nothing and
     * runs nothing when there is none, which is the case.
     */
    private static final List<String> ALLOWED =
            List.of("org.springframework.modulith.core.config.ApplicationModuleInitializerRuntimeVerification");

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
}

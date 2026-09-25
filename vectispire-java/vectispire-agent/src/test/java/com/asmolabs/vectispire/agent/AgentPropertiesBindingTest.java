package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

/**
 * The agent's settings as Spring binds them, not as a test constructs them.
 *
 * <p>Every test built {@link AgentProperties} with {@code new}, so none saw that the binder could
 * not: a second constructor left it without one to choose, and the agent image refused to start.
 */
@DisplayName("agent properties binding")
class AgentPropertiesBindingTest {

    @Test
    @DisplayName("binds from configuration, defaults included")
    void bindsLikeTheApplicationDoes() {
        var source = new MapConfigurationPropertySource(Map.of(
                "vectispire.agent.url", "http://control-plane:3180/",
                "vectispire.agent.token", " t ",
                "vectispire.agent.images.syft", "registry.internal/syft:1"));

        AgentProperties bound = new Binder(source).bind("vectispire.agent", AgentProperties.class).get();

        assertThat(bound.url()).isEqualTo("http://control-plane:3180");
        assertThat(bound.token()).isEqualTo("t");
        assertThat(bound.claimWait()).isEqualTo(Duration.ofSeconds(30));
        assertThat(bound.images().syft()).isEqualTo("registry.internal/syft:1");
    }
}

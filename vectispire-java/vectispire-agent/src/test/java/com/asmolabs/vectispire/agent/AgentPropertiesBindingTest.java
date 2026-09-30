package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

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
        assertThat(bound.images().pluginSignatureRequired())
                .as("an agent refuses unsigned plugins unless told otherwise (decision 0017 §9.1)")
                .isTrue();
    }

    @Test
    @DisplayName("the shipped configuration requires a plugin's signer unless VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED says false")
    void shippedConfigurationRequiresASigner() throws Exception {
        var sources = new YamlPropertySourceLoader().load("agent", new ClassPathResource("application.yaml"));
        var environment = new StandardEnvironment();
        sources.forEach(environment.getPropertySources()::addLast);

        assertThat(environment.getProperty("vectispire.agent.images.plugin-signature-required", Boolean.class))
                .as("the default is the application's, not the operator's")
                .isTrue();

        environment.getPropertySources().addFirst(new MapPropertySource("operator",
                Map.of("VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED", "false")));
        assertThat(environment.getProperty("vectispire.agent.images.plugin-signature-required", Boolean.class))
                .as("the operator's explicit false is still honoured")
                .isFalse();
    }
}

package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;

/**
 * The agent's settings as Spring binds them, not as a test constructs them.
 *
 * <p>Every test built {@link AgentProperties} with {@code new}, so none saw that the binder could
 * not: a second constructor left it without one to choose, and the agent image refused to start.
 */
@DisplayName("agent properties binding")
class AgentPropertiesBindingTest {

    private final Logger logger = (Logger) LoggerFactory.getLogger(AgentProperties.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();

    @BeforeEach
    void listen() {
        logged.start();
        logger.addAppender(logged);
    }

    @AfterEach
    void stopListening() {
        logger.detachAppender(logged);
    }

    private static AgentProperties bind(Map<String, String> values) {
        return new Binder(new MapConfigurationPropertySource(values))
                .bind("vectispire.agent", AgentProperties.class)
                .get();
    }

    private List<String> warnings() {
        return logged.list.stream()
                .filter(event -> event.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    @Test
    @DisplayName("a duration within its bounds is taken as written, and nothing is said")
    void withinBoundsIsSilent() {
        AgentProperties bound = bind(Map.of(
                "vectispire.agent.claim-wait", "1s",
                "vectispire.agent.retry-delay", "5m",
                "vectispire.agent.heartbeat", "5s"));

        assertThat(bound.claimWait()).isEqualTo(Duration.ofSeconds(1));
        assertThat(bound.retryDelay()).isEqualTo(Duration.ofMinutes(5));
        assertThat(bound.heartbeat()).isEqualTo(Duration.ofSeconds(5));
        assertThat(warnings()).isEmpty();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(AgentProperties.class)
    static class Bound {}

    @Test
    @DisplayName("a bare number is milliseconds: under the floor, the start is refused naming the property")
    void underTheFloorStopsTheStart() {
        new ApplicationContextRunner()
                .withUserConfiguration(Bound.class)
                .withPropertyValues("vectispire.agent.claim-wait=30")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasMessageContaining("vectispire.agent")
                            .rootCause()
                            .hasMessage("vectispire.agent.claim-wait (VECTISPIRE_AGENT_WAIT) is 30ms, under its floor "
                                    + "of 1s: the agent does not start. A bare number is read as milliseconds; "
                                    + "write the unit, as in 30s.");
                });
    }

    @Test
    @DisplayName("each duration has its own floor, and a value just under it is refused by its own name")
    void eachFloorRefusesByName() {
        assertThatThrownBy(() -> bind(Map.of("vectispire.agent.retry-delay", "0s")))
                .rootCause()
                .hasMessageStartingWith("vectispire.agent.retry-delay (VECTISPIRE_AGENT_RETRY) is 0s, under its floor of 1s");
        assertThatThrownBy(() -> bind(Map.of("vectispire.agent.heartbeat", "4s")))
                .rootCause()
                .hasMessageStartingWith("vectispire.agent.heartbeat (VECTISPIRE_AGENT_HEARTBEAT) is 4s, under its floor of 5s");
        assertThatThrownBy(() -> bind(Map.of("vectispire.agent.claim-wait", "999ms")))
                .rootCause()
                .hasMessageStartingWith("vectispire.agent.claim-wait (VECTISPIRE_AGENT_WAIT) is 999ms, under its floor of 1s");
    }

    @Test
    @DisplayName("a value over the ceiling is lowered to it, and the start says so by name")
    void overTheCeilingIsLoweredAloud() {
        AgentProperties bound = bind(Map.of(
                "vectispire.agent.heartbeat", "1h",
                "vectispire.agent.claim-wait", "6m"));

        assertThat(bound.heartbeat()).isEqualTo(Duration.ofMinutes(10));
        assertThat(bound.claimWait()).isEqualTo(Duration.ofMinutes(5));
        assertThat(warnings()).containsExactlyInAnyOrder(
                "vectispire.agent.heartbeat (VECTISPIRE_AGENT_HEARTBEAT) is 60m, over its ceiling of 10m: "
                        + "the agent uses 10m.",
                "vectispire.agent.claim-wait (VECTISPIRE_AGENT_WAIT) is 6m, over its ceiling of 5m: the agent uses 5m.");
    }

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

    @Test
    @DisplayName("the executor is Docker unless the chart's variables say Kubernetes")
    void theExecutorBindsFromTheShippedConfiguration() throws Exception {
        var sources = new YamlPropertySourceLoader().load("agent", new ClassPathResource("application.yaml"));
        var environment = new StandardEnvironment();
        sources.forEach(environment.getPropertySources()::addLast);
        AgentProperties plain = Binder.get(environment).bind("vectispire.agent", AgentProperties.class).get();
        assertThat(plain.executor().kind()).isEqualTo("docker");

        // The variables the chart's Kubernetes shape sets on the agent's container.
        environment.getPropertySources().addFirst(new MapPropertySource("chart", Map.of(
                "VECTISPIRE_AGENT_EXECUTOR", "kubernetes",
                "VECTISPIRE_SCANS_NAMESPACE", "vectispire-scans",
                "VECTISPIRE_AGENT_NAME", "vs-vectispire",
                "VECTISPIRE_KUBERNETES_START_TIMEOUT", "7m",
                "VECTISPIRE_KUBERNETES_PLACEMENT", "{\"nodeSelector\":{\"pool\":\"scans\"}}")));
        AgentProperties.Executor executor = Binder.get(environment).bind("vectispire.agent", AgentProperties.class).get().executor();
        assertThat(executor.kind()).isEqualTo("kubernetes");
        assertThat(executor.kubernetes().namespace()).isEqualTo("vectispire-scans");
        assertThat(executor.kubernetes().name()).isEqualTo("vs-vectispire");
        assertThat(executor.kubernetes().startTimeout()).isEqualTo(Duration.ofMinutes(7));
        assertThat(executor.kubernetes().placement()).isEqualTo("{\"nodeSelector\":{\"pool\":\"scans\"}}");
    }
}

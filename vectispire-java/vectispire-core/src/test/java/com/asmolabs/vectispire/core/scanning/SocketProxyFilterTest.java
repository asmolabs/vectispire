package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.yaml.snakeyaml.Yaml;

/**
 * The socket proxies' filter in the shipped {@code docker-compose.yml}, section by section.
 *
 * <p><b>Every section named, none left to the image.</b> The image's defaults are not all closed:
 * {@code EVENTS} is {@code 1} unless the composition says otherwise, and for a while it did not —
 * while decision 0018 said everything outside the six sections Vectispire calls was refused. The
 * list below is every section the pinned image's HAProxy configuration reads; a new one in a later
 * image belongs here, read off that configuration, before the pin moves.
 */
@DisplayName("the shipped socket proxies' filter")
class SocketProxyFilterTest {

    private static final Path COMPOSE = Path.of("../../docker-compose.yml");

    /** What {@code ContainerRunner} calls, and nothing else. */
    private static final Set<String> OPEN = Set.of("PING", "VERSION", "INFO", "CONTAINERS", "IMAGES", "POST");

    /** Every API section `tecnativa/docker-socket-proxy:v0.5.0`'s haproxy.cfg reads. */
    private static final Set<String> SECTIONS = Set.of(
            "AUTH", "BUILD", "COMMIT", "CONFIGS", "CONTAINERS", "DISTRIBUTION", "EVENTS", "EXEC", "GRPC",
            "IMAGES", "INFO", "NETWORKS", "NODES", "PING", "PLUGINS", "POST", "SECRETS", "SERVICES",
            "SESSION", "SWARM", "SYSTEM", "TASKS", "VERSION", "VOLUMES");

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"docker-proxy", "agent-docker-proxy"})
    @DisplayName("opens what the runner calls, and names every other section closed")
    void everySectionIsADecision(String service) throws IOException {
        Map<String, String> environment = environmentOf(service);

        assertThat(environment.keySet())
                .as("%s leaves a section to the image's default, which is not always 0", service)
                .containsAll(SECTIONS);
        Map<String, String> open = new TreeMap<>();
        environment.forEach((section, value) -> {
            if (SECTIONS.contains(section) && !"0".equals(value)) {
                open.put(section, value);
            }
        });
        assertThat(open.keySet()).as("%s opens", service).isEqualTo(new java.util.TreeSet<>(OPEN));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> environmentOf(String service) throws IOException {
        try (Reader in = Files.newBufferedReader(COMPOSE)) {
            Map<String, Object> compose = new Yaml().load(in);
            Map<String, Object> services = (Map<String, Object>) compose.get("services");
            Map<String, Object> definition = (Map<String, Object>) services.get(service);
            Map<String, Object> environment = (Map<String, Object>) definition.get("environment");
            Map<String, String> values = new TreeMap<>();
            environment.forEach((key, value) -> values.put(key, String.valueOf(value)));
            return values;
        }
    }
}

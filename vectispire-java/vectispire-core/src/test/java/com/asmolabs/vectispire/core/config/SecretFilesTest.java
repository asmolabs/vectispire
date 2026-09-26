package com.asmolabs.vectispire.core.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;

/**
 * The secrets the shipped compose hands over as files, read as the variables they replace.
 *
 * <p>The compose file moved them out of the environment, where the daemon's inspect showed them to
 * every client of the socket proxy. If Spring did not pick the files up, the control plane would
 * start with no encryption key and no database password — so this is checked, not assumed.
 */
@DisplayName("secrets under /run/secrets")
class SecretFilesTest {

    @Configuration(proxyBeanMethods = false)
    static class Nothing {}

    @Test
    @DisplayName("the shipped configuration imports /run/secrets as a config tree")
    void theImportIsShipped() throws Exception {
        var sources = new YamlPropertySourceLoader().load("application", new ClassPathResource("application.yaml"));

        assertThat(sources.getFirst().getProperty("spring.config.import"))
                .hasToString("optional:configtree:/run/secrets/");
    }

    @Test
    @DisplayName("a file named after a variable answers that variable's placeholder, without its newline")
    void aFileAnswersThePlaceholder(@TempDir Path secrets) throws Exception {
        Files.writeString(secrets.resolve("VECTISPIRE_DB_PASSWORD"), "from-a-file\n");
        Files.writeString(secrets.resolve("VECTISPIRE_BOOTSTRAP_PASSWORD"), "first-hand-off");

        try (ConfigurableApplicationContext context = new SpringApplicationBuilder(Nothing.class)
                .web(WebApplicationType.NONE)
                .properties(Map.of("spring.main.banner-mode", "off"))
                .run("--spring.config.import=optional:configtree:" + secrets + "/")) {
            Environment environment = context.getEnvironment();

            assertThat(environment.getProperty("spring.datasource.password")).isEqualTo("from-a-file");
            assertThat(environment.getProperty("vectispire.bootstrap.password")).isEqualTo("first-hand-off");
        }
    }

    @Test
    @DisplayName("a file named after a property answers that property: the signing key, whole, and the OIDC secret")
    void aFileAnswersTheProperty(@TempDir Path secrets) throws Exception {
        // Neither is a placeholder in application.yaml, so neither can be answered by a file named
        // after its variable: the file carries the property's own name.
        String pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----";
        Files.writeString(secrets.resolve("vectispire.signing.key"), pem + "\n");
        Files.writeString(secrets.resolve("vectispire.oidc.client-secret"), "client-secret-from-a-file");

        try (ConfigurableApplicationContext context = new SpringApplicationBuilder(Nothing.class)
                .web(WebApplicationType.NONE)
                .properties(Map.of("spring.main.banner-mode", "off"))
                .run("--spring.config.import=optional:configtree:" + secrets + "/")) {
            Environment environment = context.getEnvironment();

            // A multi-line value keeps its final newline (the tree trims single lines only), and
            // SigningKeyService strips what it reads.
            assertThat(environment.getProperty("vectispire.signing.key")).isEqualTo(pem + "\n");
            assertThat(environment.getProperty("vectispire.oidc.client-secret")).isEqualTo("client-secret-from-a-file");
        }
    }

    @Test
    @DisplayName("the shipped compose hands the signing key and the OIDC secret over as files, never as environment")
    @SuppressWarnings("unchecked")
    void theComposeKeepsThemOutOfTheEnvironment() throws Exception {
        // As variables they were one `docker inspect` away from every client of the socket proxy —
        // the key signs every evidence bundle, the secret speaks for the instance to the provider.
        Path root = Path.of("").toAbsolutePath();
        while (!Files.exists(root.resolve("docker-compose.yml"))) {
            root = root.getParent();
        }
        Map<String, Object> compose = new org.yaml.snakeyaml.Yaml().load(Files.readString(root.resolve("docker-compose.yml")));
        Map<String, Object> controlPlane = (Map<String, Object>) ((Map<String, Object>) compose.get("services")).get("control-plane");

        assertThat(((Map<String, Object>) controlPlane.get("environment")).keySet())
                .noneMatch(name -> name.contains("SIGNING_KEY") || name.contains("CLIENT_SECRET"));
        assertThat((java.util.List<Object>) controlPlane.get("secrets"))
                .map(secret -> secret instanceof Map<?, ?> long_ ? String.valueOf(long_.get("target")) : String.valueOf(secret))
                .contains("vectispire.signing.key", "vectispire.oidc.client-secret");
        // `.env.oidc` becomes the container's environment: the example must not teach the secret there.
        assertThat(Files.readAllLines(root.resolve(".env.oidc.example")))
                .noneMatch(line -> line.startsWith("VECTISPIRE_OIDC_CLIENT_SECRET"));
    }
}

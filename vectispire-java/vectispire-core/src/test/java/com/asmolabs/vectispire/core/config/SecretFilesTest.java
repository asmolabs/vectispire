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
}

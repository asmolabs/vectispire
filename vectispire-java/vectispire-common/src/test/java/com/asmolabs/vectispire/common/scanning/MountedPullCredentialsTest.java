package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A pull secret mounted into the Kubernetes agent, read as the Docker executor reads its daemon's
 * configuration: the entry the pull would use, and that one alone leaves.
 */
@DisplayName("pull credentials read from a mounted Docker configuration")
class MountedPullCredentialsTest {

    private static final String IMAGE = "registry.acme.internal:5000/security/acme-lint@sha256:" + "d".repeat(64);
    private static final String PASSWORD = "s3cret-pull-password"; // gitleaks:allow — invented for this test
    private static final String OTHER_PASSWORD = "other-registry-password"; // gitleaks:allow — invented for this test

    @TempDir
    Path directory;

    private Path secret() throws IOException {
        Path mounted = Files.createDirectories(directory.resolve("registry"));
        Files.writeString(mounted.resolve("config.json"), """
                {"auths": {
                  "registry.acme.internal:5000": {"auth": "%s"},
                  "other.acme.internal": {"auth": "%s"}
                }}""".formatted(basic("robot", PASSWORD), basic("someone", OTHER_PASSWORD)));
        return mounted;
    }

    private static String basic(String user, String password) {
        return Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void theImagesRegistryIsWrittenAlone_readableByItsOwnerOnly() throws IOException {
        MountedPullCredentials credentials = MountedPullCredentials.of(secret(), IMAGE).orElseThrow();
        assertThat(credentials.registry()).isEqualTo("registry.acme.internal:5000");

        Path written = credentials.writeUnder(directory.resolve("workspace"));
        JsonNode config = new ObjectMapper().readTree(written.resolve("config.json").toFile());
        assertThat(config.path("auths").properties()).hasSize(1);
        assertThat(config.path("auths").path("registry.acme.internal:5000").path("auth").asText())
                .isEqualTo(basic("robot", PASSWORD));
        assertThat(Files.readString(written.resolve("config.json"))).doesNotContain(basic("someone", OTHER_PASSWORD));
        assertThat(Files.getPosixFilePermissions(written.resolve("config.json")))
                .isEqualTo(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));

        MountedPullCredentials.erase(written);
        assertThat(written).doesNotExist();
    }

    @Test
    void aRegistryTheSecretDoesNotNameHasNothing_andNoSecretHasNothing() throws IOException {
        assertThat(MountedPullCredentials.of(secret(), "ghcr.io/acme/lint@sha256:" + "e".repeat(64))).isEmpty();
        assertThat(MountedPullCredentials.of(null, IMAGE)).isEmpty();
    }

    @Test
    void anEntryWithoutCredentialsIsNone_asTheDockerExecutorReadsIt() throws IOException {
        // What a credential helper leaves in config.json: the registry named, its secret elsewhere.
        Path mounted = Files.createDirectories(directory.resolve("helper"));
        Files.writeString(mounted.resolve("config.json"),
                "{\"auths\": {\"registry.acme.internal:5000\": {}}, \"credsStore\": \"desktop\"}");
        assertThat(MountedPullCredentials.of(mounted, IMAGE)).isEmpty();
    }

    @Test
    void aBrokenSecretSaysSo_ratherThanReadingAnonymously() throws IOException {
        Path mounted = Files.createDirectories(directory.resolve("broken"));
        Files.writeString(mounted.resolve("config.json"), "{\"auths\": ");
        assertThatThrownBy(() -> MountedPullCredentials.of(mounted, IMAGE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(mounted.toString());
    }

    @Test
    void whatAToolQuotesIsRedacted_inBothForms() throws IOException {
        MountedPullCredentials credentials = MountedPullCredentials.of(secret(), IMAGE).orElseThrow();
        assertThat(credentials.redact("sent " + PASSWORD + " and " + basic("robot", PASSWORD)))
                .isEqualTo("sent [redacted] and [redacted]");
        assertThat(credentials.toString()).doesNotContain(PASSWORD).contains("registry.acme.internal:5000");
    }

    @Test
    void onlyAConfigJsonIsReadable() throws IOException {
        Path mounted = Files.createDirectories(directory.resolve("as-mounted"));
        Files.writeString(mounted.resolve(".dockerconfigjson"), "{}");
        assertThat(MountedPullCredentials.readable(mounted)).isFalse();
        assertThat(MountedPullCredentials.readable(secret())).isTrue();
    }
}

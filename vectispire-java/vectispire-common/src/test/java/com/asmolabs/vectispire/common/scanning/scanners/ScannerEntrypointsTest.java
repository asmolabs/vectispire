package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Every entrypoint {@link ScannerImages} declares is the one its pinned image carries.
 *
 * <p><b>Docker never reads the declarations, so nothing else would notice one going wrong.</b> The
 * Kubernetes executor runs the declared program through a wrapper that captures its output (decision
 * 0045): a digest refreshed onto an image whose binary moved would fail every scan there, and only there.
 * Read from the registry's image configuration — {@code docker buildx imagetools inspect}, no layer
 * pulled — for every platform the index carries, since an entrypoint may differ between them.
 */
@DisplayName("scanner entrypoints")
class ScannerEntrypointsTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    static Stream<Arguments> declarations() {
        ScannerImages pinned = ScannerImages.PINNED;
        return Stream.of(
                Arguments.of("syft", pinned.syft(), ScannerImages.SYFT_ENTRYPOINT),
                Arguments.of("grype", pinned.grype(), ScannerImages.GRYPE_ENTRYPOINT),
                Arguments.of("gitleaks", pinned.gitleaks(), ScannerImages.GITLEAKS_ENTRYPOINT),
                Arguments.of("checkov", pinned.checkov(), ScannerImages.CHECKOV_ENTRYPOINT),
                Arguments.of("semgrep", pinned.semgrep(), ScannerImages.SEMGREP_ENTRYPOINT));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("declarations")
    void theDeclaredEntrypointIsTheImages(String tool, String image, List<String> declared) throws Exception {
        JsonNode inspected = JSON.readTree(imageConfiguration(image));
        // One configuration per platform for an index, the configuration itself for a single manifest.
        List<JsonNode> configurations = new ArrayList<>();
        if (inspected.has("config")) {
            configurations.add(inspected);
        } else {
            inspected.forEach(configurations::add);
        }
        assertThat(configurations).as("platforms of %s", image).isNotEmpty();
        for (JsonNode configuration : configurations) {
            List<String> entrypoint = new ArrayList<>();
            configuration.path("config").path("Entrypoint").forEach(part -> entrypoint.add(part.asText()));
            assertThat(entrypoint).as("%s's entrypoint", tool).isEqualTo(declared);
        }
    }

    private static String imageConfiguration(String image) throws IOException, InterruptedException {
        Process process = new ProcessBuilder("docker", "buildx", "imagetools", "inspect", image, "--format", "{{json .Image}}")
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(2, TimeUnit.MINUTES) || process.exitValue() != 0) {
            // A failure, never a skip: a check that cannot reach the registry has checked nothing.
            throw new IllegalStateException("docker buildx imagetools inspect " + image + " failed: " + output);
        }
        return output;
    }
}

package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
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
 * Read from the registry's image configuration for every platform the index carries, since an entrypoint
 * may differ between them.
 *
 * <p><b>Over HTTP with the JDK, not the Docker CLI</b>: CI's {@code jvm} job runs in a JDK container with
 * no {@code docker} at all, and the first version, which shelled out to {@code docker buildx imagetools},
 * passed on a developer's machine and failed there. Anonymous, from Docker Hub, where the pinned images live;
 * the configuration is the blob the digest names, so what is read is what is pinned.
 */
@DisplayName("scanner entrypoints")
class ScannerEntrypointsTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String REGISTRY = "https://registry-1.docker.io/v2/";
    private static final String MANIFESTS = String.join(", ",
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json");
    // Blobs are served by a redirect to the registry's storage; nothing here carries a credential but the
    // anonymous pull token, which is the registry's own and scoped to one public repository.
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(20))
            .build();

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
        List<JsonNode> configurations = configurations(image);
        assertThat(configurations).as("platforms of %s", image).isNotEmpty();
        for (JsonNode configuration : configurations) {
            List<String> entrypoint = new ArrayList<>();
            configuration.path("config").path("Entrypoint").forEach(part -> entrypoint.add(part.asText()));
            assertThat(entrypoint).as("%s's entrypoint", tool).isEqualTo(declared);
        }
    }

    /** The image configuration of each Linux platform of {@code image}, a Docker Hub reference by digest. */
    private static List<JsonNode> configurations(String image) throws IOException, InterruptedException {
        int at = image.indexOf('@');
        String repository = image.substring(0, at);
        String digest = image.substring(at + 1);
        if (repository.indexOf('/') < 0 || repository.substring(0, repository.indexOf('/')).contains(".")) {
            throw new IllegalStateException(image + " is not a Docker Hub repository with a namespace: read it elsewhere.");
        }
        String token = JSON.readTree(get("https://auth.docker.io/token?service=registry.docker.io&scope="
                + URLEncoder.encode("repository:" + repository + ":pull", StandardCharsets.UTF_8), null, null))
                .path("token").asText();
        JsonNode manifest = JSON.readTree(get(REGISTRY + repository + "/manifests/" + digest, token, MANIFESTS));
        List<JsonNode> configurations = new ArrayList<>();
        if (manifest.has("manifests")) {
            for (JsonNode entry : manifest.path("manifests")) {
                // An index also lists attestations, as platform unknown/unknown: they carry no configuration.
                if (!"linux".equals(entry.path("platform").path("os").asText())) {
                    continue;
                }
                JsonNode platform = JSON.readTree(get(REGISTRY + repository + "/manifests/" + entry.path("digest").asText(),
                        token, MANIFESTS));
                configurations.add(configuration(repository, platform, token));
            }
        } else {
            configurations.add(configuration(repository, manifest, token));
        }
        return configurations;
    }

    private static JsonNode configuration(String repository, JsonNode manifest, String token)
            throws IOException, InterruptedException {
        return JSON.readTree(get(REGISTRY + repository + "/blobs/" + manifest.path("config").path("digest").asText(),
                token, null));
    }

    private static String get(String url, String token, String accept) throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMinutes(1)).GET();
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        if (accept != null) {
            request.header("Accept", accept);
        }
        HttpResponse<String> response = HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            // A failure, never a skip: a check that cannot reach the registry has checked nothing.
            throw new IllegalStateException("GET " + url.replaceFirst("\\?.*", "") + " answered " + response.statusCode());
        }
        return response.body();
    }
}

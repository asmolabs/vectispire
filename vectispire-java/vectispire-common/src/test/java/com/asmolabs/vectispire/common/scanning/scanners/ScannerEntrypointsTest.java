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
 * passed on a developer's machine and failed there. Anonymous, through the registry's own token challenge —
 * Docker Hub for the scanners, gcr.io for crane; the configuration is the blob the digest names, so what is
 * read is what is pinned.
 */
@DisplayName("scanner entrypoints")
class ScannerEntrypointsTest {

    private static final ObjectMapper JSON = new ObjectMapper();

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
                Arguments.of("semgrep", pinned.semgrep(), ScannerImages.SEMGREP_ENTRYPOINT),
                Arguments.of("crane", ScannerImages.CRANE, ScannerImages.CRANE_ENTRYPOINT));
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

    /** The image configuration of each Linux platform of {@code image}, a reference by digest. */
    private static List<JsonNode> configurations(String image) throws IOException, InterruptedException {
        int at = image.indexOf('@');
        String name = image.substring(0, at);
        String digest = image.substring(at + 1);
        String first = name.substring(0, name.indexOf('/'));
        boolean hosted = first.contains(".") || first.contains(":");
        String registry = hosted ? "https://" + first + "/v2/" : "https://registry-1.docker.io/v2/";
        String repository = hosted ? name.substring(first.length() + 1) : name;
        String token = token(registry, repository);
        JsonNode manifest = JSON.readTree(get(registry + repository + "/manifests/" + digest, token, MANIFESTS));
        List<JsonNode> configurations = new ArrayList<>();
        if (manifest.has("manifests")) {
            for (JsonNode entry : manifest.path("manifests")) {
                // An index also lists attestations, as platform unknown/unknown: they carry no configuration.
                if (!"linux".equals(entry.path("platform").path("os").asText())) {
                    continue;
                }
                JsonNode platform = JSON.readTree(get(registry + repository + "/manifests/" + entry.path("digest").asText(),
                        token, MANIFESTS));
                configurations.add(JSON.readTree(get(registry + repository + "/blobs/"
                        + platform.path("config").path("digest").asText(), token, null)));
            }
        } else {
            configurations.add(JSON.readTree(get(registry + repository + "/blobs/"
                    + manifest.path("config").path("digest").asText(), token, null)));
        }
        return configurations;
    }

    /**
     * An anonymous pull token, from wherever the registry's challenge says: {@code GET /v2/} answers 401 with
     * {@code WWW-Authenticate: Bearer realm="…",service="…"}, as Docker Hub and gcr.io both do.
     */
    private static String token(String registry, String repository) throws IOException, InterruptedException {
        HttpResponse<String> challenge = HTTP.send(HttpRequest.newBuilder(URI.create(registry)).timeout(Duration.ofMinutes(1))
                .GET().build(), HttpResponse.BodyHandlers.ofString());
        String header = challenge.headers().firstValue("WWW-Authenticate").orElseThrow(() ->
                new IllegalStateException(registry + " answered " + challenge.statusCode() + " with no challenge"));
        java.util.regex.Matcher realm = java.util.regex.Pattern.compile("realm=\"([^\"]+)\"").matcher(header);
        java.util.regex.Matcher service = java.util.regex.Pattern.compile("service=\"([^\"]+)\"").matcher(header);
        if (!realm.find()) {
            throw new IllegalStateException(registry + "'s challenge names no realm: " + header);
        }
        String url = realm.group(1) + "?scope=" + URLEncoder.encode("repository:" + repository + ":pull", StandardCharsets.UTF_8)
                + (service.find() ? "&service=" + URLEncoder.encode(service.group(1), StandardCharsets.UTF_8) : "");
        JsonNode answer = JSON.readTree(get(url, null, null));
        return answer.hasNonNull("token") ? answer.path("token").asText() : answer.path("access_token").asText();
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

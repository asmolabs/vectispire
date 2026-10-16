package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The container-create request the secrets scan sends the daemon, as the daemon receives it — for the
 * Rust port's runner to send the same (see {@code ReferenceSet}).
 *
 * <p><b>Captured off the wire, not off the builder.</b> {@code ContainerHardeningTest} asserts what
 * {@code ContainerRunner} asks docker-java for; what matters to the daemon, and what the Rust runner
 * has to reproduce, is the JSON docker-java then writes — the capability list it expands, the fields
 * it leaves out. So the daemon here is a stub on a loopback port that answers the image inspection
 * and {@code info}, records the create, and refuses it, which ends the run before anything starts.
 *
 * <p>The workspace's path and owner differ on every machine and are written as placeholders; the Rust
 * test puts them back the same way.
 */
class ContainerReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    /** Fixed, so the CPU quota does not depend on the machine: the stub daemon reports eight cores. */
    static final ScannerLimits LIMITS = new ScannerLimits(
            2048L * 1024 * 1024, 512, Duration.ofMinutes(15), 3_000_000_000L, ScannerLimits.DEFAULT_OUTPUT_BYTES);

    @Test
    void theSecretsScanCreatesThisContainer() throws Exception {
        List<String> creates = new ArrayList<>();
        List<String> createPaths = new ArrayList<>();
        HttpServer daemon = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        daemon.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            byte[] answer;
            int status;
            if (path.endsWith("/containers/create")) {
                creates.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                createPaths.add(path.replaceFirst("^/v[0-9.]+", "") + (exchange.getRequestURI().getRawQuery() == null
                        ? "" : "?" + exchange.getRequestURI().getRawQuery()));
                status = 500;
                answer = "{\"message\":\"reference stub: not created\"}".getBytes(StandardCharsets.UTF_8);
            } else if (path.endsWith("/info")) {
                status = 200;
                answer = "{\"NCPU\":8}".getBytes(StandardCharsets.UTF_8);
            } else if (path.contains("/images/") && path.endsWith("/json")) {
                status = 200;
                answer = "{\"Id\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"}"
                        .getBytes(StandardCharsets.UTF_8);
            } else {
                status = 404;
                answer = "{\"message\":\"not stubbed\"}".getBytes(StandardCharsets.UTF_8);
            }
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, answer.length);
            exchange.getResponseBody().write(answer);
            exchange.close();
        });
        daemon.start();
        try {
            ContainerRunner runner = new ContainerRunner(
                    ContainerRunner.clientAt("tcp://127.0.0.1:" + daemon.getAddress().getPort()), LIMITS);
            SecretsScanner scanner = new SecretsScanner(runner, ScannerImages.PINNED.gitleaks());
            Workspace.withWorkspace(workspace -> {
                assertThatThrownBy(() -> scanner.scan(workspace, null)).isInstanceOf(RuntimeException.class);
                String owner = ContainerRun.ownerOf(workspace.root()).orElseThrow();
                assertThat(creates).hasSize(1);
                try {
                    String body = creates.getFirst()
                            .replace(workspace.root().toRealPath().toString(), "{workspace}")
                            .replace(workspace.root().toString(), "{workspace}")
                            .replace("\"" + owner + "\"", "\"{owner}\"");
                    JsonNode tree = JSON.readTree(body);
                    ObjectNode recorded = JSON.createObjectNode();
                    recorded.put("path", createPaths.getFirst());
                    recorded.set("body", tree);
                    // Through a map, so ORDER_MAP_ENTRIES_BY_KEYS sorts every level the same way the Rust
                    // side's serde_json::Value prints.
                    Object sorted = JSON.treeToValue(recorded, Object.class);
                    ReferenceSet.expect("container/secrets-scan-create.json", JSON.writeValueAsString(sorted) + "\n");
                } catch (Exception unreadable) {
                    throw new IllegalStateException(unreadable);
                }
                return null;
            });
        } finally {
            daemon.stop(0);
        }
    }
}

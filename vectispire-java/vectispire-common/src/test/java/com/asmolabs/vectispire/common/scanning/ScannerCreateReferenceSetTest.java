package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.asmolabs.vectispire.common.scanning.scanners.IacScanner;
import com.asmolabs.vectispire.common.scanning.scanners.SastScanner;
import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.Test;

/**
 * The container-create requests of the IaC and SAST scans, as the daemon receives them — for the Rust
 * port's runner to send the same. Captured off the wire by a stub daemon, as
 * {@code ContainerReferenceSetTest} captures the secrets scan's, with the same limits and placeholders.
 *
 * <p>A sub-path is passed, so the reference also pins how it reaches the command line.
 */
class ScannerCreateReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

    @Test
    void theIacScanCreatesThisContainer() throws Exception {
        capture("container/iac-scan-create.json", (runner, workspace) ->
                new IacScanner(runner, ScannerImages.PINNED.checkov()).scan(workspace, "deploy"));
    }

    @Test
    void theSastScanCreatesThisContainer() throws Exception {
        capture("container/sast-scan-create.json", (runner, workspace) -> {
            try {
                new SastScanner(runner, ScannerImages.PINNED.semgrep()).scan(workspace, "service");
            } catch (RuntimeException refusedByTheStub) {
                // The stub refuses the create: the request is what is recorded.
            }
        });
    }

    private static void capture(String reference, BiConsumer<ContainerRunner, Workspace> scan) throws Exception {
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
                    ContainerRunner.clientAt("tcp://127.0.0.1:" + daemon.getAddress().getPort()),
                    ContainerReferenceSetTest.LIMITS);
            Workspace.withWorkspace(workspace -> {
                scan.accept(runner, workspace);
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
                    Object sorted = JSON.treeToValue(recorded, Object.class);
                    ReferenceSet.expect(reference, JSON.writeValueAsString(sorted) + "\n");
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

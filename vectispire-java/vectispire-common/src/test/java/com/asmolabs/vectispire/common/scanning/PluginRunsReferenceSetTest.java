package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.plugins.PluginSignature;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.asmolabs.vectispire.common.scanning.scanners.ImageSignatureVerifier;
import com.asmolabs.vectispire.common.scanning.scanners.PluginScanner;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What the Rust port's runner must do with a plugin's container, held to this side's answers (see
 * {@code ReferenceSet}): read the one file a bounded output holds back from the daemon's archive,
 * believe the holder's {@code df}, resolve and hand over the pull credentials as docker-java resolves
 * them, and send the daemon the create requests — the holder of the bounded output, the plugin beside
 * it, cosign with its registry login — that this runner sends.
 *
 * <p>The archives are built here and written into the answers whole, base64: the reader's input is
 * those bytes and nothing else. The create requests are captured off the wire, as
 * {@code ContainerReferenceSetTest} captures the secrets scan's.
 */
class PluginRunsReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ObjectMapper SORTED = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    @TempDir
    Path temporary;

    // ----------------------------------------------------------------------------------------------
    // The archive a bounded output is read back through

    private static byte[] header(String name, long size, char type, String prefix) {
        byte[] header = new byte[512];
        byte[] bytes = name.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(bytes, 0, header, 0, Math.min(bytes.length, 100));
        byte[] mode = "0000644".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(mode, 0, header, 100, mode.length);
        byte[] octal = String.format("%011o", size).getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(octal, 0, header, 124, octal.length);
        header[156] = (byte) type;
        System.arraycopy("ustar".getBytes(StandardCharsets.US_ASCII), 0, header, 257, 5);
        if (prefix != null) {
            byte[] p = prefix.getBytes(StandardCharsets.UTF_8);
            System.arraycopy(p, 0, header, 345, Math.min(p.length, 155));
        }
        return header;
    }

    private static byte[] header(String name, long size, char type) {
        return header(name, size, type, null);
    }

    private static byte[] base256(String name, long size) {
        byte[] header = header(name, 0, '0');
        java.util.Arrays.fill(header, 124, 136, (byte) 0);
        header[124] = (byte) 0x80;
        for (int i = 135; i > 124 && size > 0; i--) {
            header[i] = (byte) (size & 0xff);
            size >>>= 8;
        }
        return header;
    }

    private static byte[] padded(byte[] content) {
        int length = (content.length + 511) / 512 * 512;
        return java.util.Arrays.copyOf(content, length);
    }

    private static byte[] tar(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part.length % 512 == 0 ? part : padded(part));
        }
        return out.toByteArray();
    }

    private static byte[] text(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static String pax(String key, String value) {
        String body = " " + key + "=" + value + "\n";
        int length = body.getBytes(StandardCharsets.UTF_8).length;
        int total = length + String.valueOf(length).length();
        if (String.valueOf(total).length() != String.valueOf(length).length()) {
            total++;
        }
        return total + body;
    }

    private static final byte[] END = new byte[1024];
    private static final String REPORT = "{\"version\":\"2.1.0\",\"runs\":[]}";

    @Test
    void theArchivesTheDaemonAnswers() throws Exception {
        List<Object[]> cases = new ArrayList<>();
        cases.add(new Object[] {"regular", tar(header("results.sarif", REPORT.length(), '0'), text(REPORT), END), 1024L});
        cases.add(new Object[] {"regular-nul-type", tar(header("results.sarif", REPORT.length(), '\0'), text(REPORT), END), 1024L});
        cases.add(new Object[] {"empty-file", tar(header("results.sarif", 0, '0'), END), 1024L});
        cases.add(new Object[] {"at-ceiling", tar(header("results.sarif", REPORT.length(), '0'), text(REPORT), END), (long) REPORT.length()});
        cases.add(new Object[] {"over-ceiling", tar(header("results.sarif", REPORT.length(), '0'), text(REPORT), END), (long) REPORT.length() - 1});
        cases.add(new Object[] {"symlink", tar(header("results.sarif", 0, '2'), END), 1024L});
        cases.add(new Object[] {"hard-link", tar(header("results.sarif", 0, '1'), END), 1024L});
        cases.add(new Object[] {"directory", tar(header("results.sarif/", 0, '5'), END), 1024L});
        cases.add(new Object[] {"fifo", tar(header("results.sarif", 0, '6'), END), 1024L});
        cases.add(new Object[] {"other-name", tar(header("other.sarif", REPORT.length(), '0'), text(REPORT), END), 1024L});
        cases.add(new Object[] {"prefixed-name", tar(header("results.sarif", REPORT.length(), '0', "output"), text(REPORT), END), 1024L});
        cases.add(new Object[] {"empty-stream", new byte[0], 1024L});
        cases.add(new Object[] {"only-end", END, 1024L});
        cases.add(new Object[] {"short-header", new byte[100], 1024L});
        cases.add(new Object[] {"truncated-content", java.util.Arrays.copyOf(header("results.sarif", 600, '0'), 512 + 10), 1024L});
        cases.add(new Object[] {"huge-octal", tar(header("results.sarif", (1L << 33) - 1, '0')), 1024L});
        cases.add(new Object[] {"base256-small", tar(base256("results.sarif", REPORT.length()), text(REPORT), END), 1024L});
        cases.add(new Object[] {"base256-huge", tar(base256("results.sarif", 1L << 40)), 1024L});
        byte[] overflow = header("results.sarif", 0, '0');
        java.util.Arrays.fill(overflow, 124, 136, (byte) 0xff);
        cases.add(new Object[] {"base256-overflow", tar(overflow), 1024L});
        byte[] garbled = header("results.sarif", 0, '0');
        System.arraycopy(text("12x45678901\0"), 0, garbled, 124, 12);
        cases.add(new Object[] {"unreadable-size", tar(garbled), 1024L});
        byte[] spaced = header("results.sarif", 0, '0');
        System.arraycopy(text("   0000034 \0"), 0, spaced, 124, 12);
        cases.add(new Object[] {"padded-octal", tar(spaced, text(REPORT.substring(0, 28)), END), 1024L});
        byte[] blank = header("results.sarif", 0, '0');
        java.util.Arrays.fill(blank, 124, 136, (byte) ' ');
        cases.add(new Object[] {"blank-size", tar(blank, END), 1024L});
        String records = pax("path", "results.sarif") + pax("size", String.valueOf(REPORT.length()));
        cases.add(new Object[] {"pax-path-and-size", tar(header("PaxHeaders/x", text(records).length, 'x'), text(records),
                header("truncated-name", 0, '0'), text(REPORT), END), 1024L});
        String unicode = pax("comment", "é€") + pax("path", "results.sarif");
        cases.add(new Object[] {"pax-unicode-record", tar(header("PaxHeaders/x", text(unicode).length, 'x'), text(unicode),
                header("x", REPORT.length(), '0'), text(REPORT), END), 1024L});
        String other = pax("path", "elsewhere/results.sarif");
        cases.add(new Object[] {"pax-other-path", tar(header("PaxHeaders/x", text(other).length, 'x'), text(other),
                header("results.sarif", REPORT.length(), '0'), text(REPORT), END), 1024L});
        cases.add(new Object[] {"pax-malformed-length", tar(header("PaxHeaders/x", 9, 'x'), text("x path=a\n"), END), 1024L});
        cases.add(new Object[] {"pax-length-too-long", tar(header("PaxHeaders/x", 12, 'x'), text("99 path=abc\n"), END), 1024L});
        cases.add(new Object[] {"pax-length-too-short", tar(header("PaxHeaders/x", 12, 'x'), text("3 path=abcd\n"), END), 1024L});
        cases.add(new Object[] {"pax-no-space", tar(header("PaxHeaders/x", 8, 'x'), text("12345678"), header("results.sarif", 2, '0'), text("{}"), END), 1024L});
        cases.add(new Object[] {"pax-bad-size", tar(header("PaxHeaders/x", text(pax("size", "x1")).length, 'x'), text(pax("size", "x1")), END), 1024L});
        cases.add(new Object[] {"pax-too-large", tar(header("PaxHeaders/x", 64 * 1024 + 1, 'x')), 1024L});
        cases.add(new Object[] {"gnu-long-name", tar(header("././@LongLink", 14, 'L'), text("results.sarif\0"),
                header("results.sar", REPORT.length(), '0'), text(REPORT), END), 1024L});
        cases.add(new Object[] {"global-pax-skipped", tar(header("pax_global_header", text(pax("comment", "x")).length, 'g'),
                text(pax("comment", "x")), header("results.sarif", REPORT.length(), '0'), text(REPORT), END), 1024L});
        cases.add(new Object[] {"pax-size-over-ceiling", tar(header("PaxHeaders/x", text(pax("size", "5000")).length, 'x'),
                text(pax("size", "5000")), header("results.sarif", 2, '0'), text("{}"), END), 1024L});
        cases.add(new Object[] {"pax-negative-size", tar(header("PaxHeaders/x", text(pax("size", "-1")).length, 'x'),
                text(pax("size", "-1")), header("results.sarif", 2, '0'), text("{}"), END), 1024L});
        cases.add(new Object[] {"invalid-utf8-name", tar(header("resultsÿ.sarif", 2, '0'), text("{}"), END), 1024L});

        ArrayNode answers = NODES.arrayNode();
        for (Object[] c : cases) {
            ObjectNode answer = answers.addObject();
            answer.put("name", (String) c[0]);
            answer.put("archive", Base64.getEncoder().encodeToString((byte[]) c[1]));
            answer.put("ceiling", (Long) c[2]);
            try {
                ContainerRunner.OutputFile file = OutputArchive.read(new ByteArrayInputStream((byte[]) c[1]), "results.sarif", (Long) c[2]);
                switch (file) {
                    case ContainerRunner.OutputFile.Read read -> answer.put("read", Base64.getEncoder().encodeToString(read.bytes()));
                    case ContainerRunner.OutputFile.Missing missing -> answer.put("missing", true);
                    case ContainerRunner.OutputFile.NotRegular notRegular -> answer.put("notRegular", true);
                    case ContainerRunner.OutputFile.TooLarge tooLarge -> answer.put("tooLarge", tooLarge.size());
                }
            } catch (IOException unreadable) {
                // The runner's sentence around it: "Its output could not be read back: " + this.
                answer.put("unreadable", unreadable.getMessage());
            }
        }
        ReferenceSet.expect("plugins/archives/answers.json", lines(answers));
    }

    @Test
    void theHoldersMeasurement() throws Exception {
        String target = "/repo/output";
        String[] printed = {
            "Filesystem           1024-blocks    Used Available Capacity Mounted on\ntmpfs                    10240      12     10228   0% /repo/output\nFilesystem              Inodes    Used Available Capacity Mounted on\ntmpfs                     4096       3      4093   0% /repo/output\n",
            "tmpfs 10240 10240 0 100% /repo/output\ntmpfs 4096 3 4093 0% /repo/output\n",
            "tmpfs 10240 10237 3 99% /repo/output\ntmpfs 4096 3 4093 0% /repo/output\n",
            "tmpfs 10240 10236 4 99% /repo/output\ntmpfs 4096 3 4093 0% /repo/output\n",
            "tmpfs 10240 12 10228 0% /repo/output\ntmpfs 4096 4096 0 100% /repo/output\n",
            "tmpfs 10240 12 10228 0% /repo/output\n",
            "",
            "tmpfs 10240 12 10228 0% /repo/output\ntmpfs 4096 3 4093 0% /repo/output\ntmpfs 4096 3 4093 0% /repo/output\n",
            "tmpfs 10240 12 10228 0% /repo/outputs\ntmpfs 4096 3 4093 0% /repo/output\n",
            "tmpfs 10240 12 -1 0% /repo/output\ntmpfs 4096 3 4093 0% /repo/output\n",
            "tmpfs 10240 12 1e3 0% /repo/output\ntmpfs 4096 3 4093 0% /repo/output\n",
            "tmpfs 10240 12 9999999999999999999 0% /repo/output\ntmpfs 4096 3 4093 0% /repo/output\n",
            "tmpfs 10240 12 999999999999999999 0% /repo/output\ntmpfs 4096 3 4093 0% /repo/output\n",
            "  tmpfs\t10240   12  10228  0%  /repo/output  \r\ntmpfs 4096 3 4093 0% /repo/output",
            "tmpfs 10240 12 10228 0% on /repo/output\ntmpfs 4096 3 4093 0% /repo/output\n",
            "df: /repo/output: No such file or directory\n",
            "tmpfs 10240 12 ١٢ 0% /repo/output\ntmpfs 4096 3 4093 0% /repo/output\n",
        };
        ArrayNode answers = NODES.arrayNode();
        ContainerRun.BoundedOutput bounded = new ContainerRun.BoundedOutput(target, 10L * 1024 * 1024, "holder", "results.sarif");
        for (String text : printed) {
            ObjectNode answer = answers.addObject();
            answer.put("printed", text);
            Optional<ContainerRunner.CollectedOutput> measured =
                    ContainerRunner.CollectedOutput.measured(bounded, text, new ContainerRunner.OutputFile.Missing());
            if (measured.isEmpty()) {
                answer.putNull("measured");
            } else {
                answer.putObject("measured")
                        .put("capacity", measured.get().capacity())
                        .put("availableBytes", measured.get().availableBytes())
                        .put("availableInodes", measured.get().availableInodes())
                        .put("full", measured.get().full());
            }
        }
        ReferenceSet.expect("plugins/measurements/answers.json", lines(answers));
    }

    // ----------------------------------------------------------------------------------------------
    // Pull credentials

    @Test
    void theCredentialsAPullWouldSend() throws Exception {
        ArrayNode answers = NODES.arrayNode();
        for (JsonNode input : JSON.readTree(ReferenceSet.read("plugins/credentials/cases.json"))) {
            Path configuration = Files.createTempDirectory(temporary, "docker-config");
            Files.writeString(configuration.resolve("config.json"), input.get("config").asText());
            ObjectNode answer = answers.addObject();
            answer.put("name", input.get("name").asText());
            ArrayNode references = answer.putArray("references");
            for (JsonNode reference : input.get("references")) {
                ObjectNode each = references.addObject();
                each.put("reference", reference.asText());
                each.put("registry", PullCredentials.registryOf(reference.asText()));
                Optional<MountedPullCredentials> credentials;
                try {
                    credentials = MountedPullCredentials.of(configuration, reference.asText());
                } catch (IllegalStateException unreadable) {
                    each.put("unreadable", true);
                    continue;
                }
                if (credentials.isEmpty()) {
                    each.putNull("configuration");
                    continue;
                }
                Path written = credentials.get().writeUnder(temporary.resolve("written"));
                each.put("entryRegistry", credentials.get().registry());
                each.put("configuration", Files.readString(written.resolve("config.json")));
                // A tool quoting all it was sent: the file, and what its auth decodes to.
                String said = "cosign said: " + Files.readString(written.resolve("config.json"))
                        + " " + decoded(Files.readString(written.resolve("config.json")));
                each.put("redacted", credentials.get().redact(said));
                MountedPullCredentials.erase(written);
            }
        }
        ReferenceSet.expect("plugins/credentials/answers.json", lines(answers));
    }

    private static String decoded(String configuration) throws IOException {
        JsonNode auth = JSON.readTree(configuration).path("auths").elements().next().path("auth");
        return auth.isMissingNode() ? "" : new String(Base64.getDecoder().decode(auth.asText()), StandardCharsets.UTF_8);
    }

    // ----------------------------------------------------------------------------------------------
    // The create requests, off the wire

    /** The stub daemon's record: each request the port has to send the same way. */
    private record Recorded(String method, String path, String body, String registryAuth) {}

    @Test
    void theContainersAPluginRunCreates() throws Exception {
        List<Recorded> requests = new ArrayList<>();
        HttpServer daemon = stub(requests, /* the holder's create succeeds, the plugin's is refused */ true);
        try {
            ContainerRunner runner = new ContainerRunner(
                    ContainerRunner.clientAt("tcp://127.0.0.1:" + daemon.getAddress().getPort()), ContainerReferenceSetTest.LIMITS);
            Path source = Files.createDirectories(temporary.resolve("workspace/source"));
            ContainerRun run = ContainerRun.of("registry.acme.internal/acme-lint@sha256:" + "d".repeat(64),
                            List.of("--out", "/repo/output/results.sarif", "/repo/source"),
                            List.of(ContainerRun.Mount.readOnly(source.toString(), "/repo/source")), "plugin acme-lint")
                    .runningAs("1000:1000")
                    .withTimeout(Duration.ofSeconds(120))
                    .withBoundedOutput(new ContainerRun.BoundedOutput("/repo/output", ScannerLimits.DEFAULT_OUTPUT_BYTES,
                            PluginScanner.OUTPUT_HOLDER, "results.sarif"));
            assertThatThrownBy(() -> runner.run(run)).isInstanceOf(RuntimeException.class);
            ReferenceSet.expect("plugins/creates/bounded-output.json", recorded(requests, temporary));
        } finally {
            daemon.stop(0);
        }
    }

    @Test
    void theContainerCosignRunsIn() throws Exception {
        List<Recorded> requests = new ArrayList<>();
        HttpServer daemon = stub(requests, false);
        try {
            Path configuration = Files.createDirectories(temporary.resolve("docker-config"));
            Files.writeString(configuration.resolve("config.json"), "{\"auths\":{\"registry.acme.internal\":{\"auth\":\""
                    + Base64.getEncoder().encodeToString(text("robot:s3cr3t")) + "\"}}}");
            ContainerRunner runner = new ContainerRunner(ContainerRunner.clientOf(DefaultDockerClientConfig.createDefaultConfigBuilder()
                    .withDockerHost("tcp://127.0.0.1:" + daemon.getAddress().getPort())
                    .withDockerConfig(configuration.toString())
                    .build()), ContainerReferenceSetTest.LIMITS);
            Path keys = temporary.resolve("workspace/plugins/acme-lint-signer");
            String reference = "registry.acme.internal/acme-lint@sha256:" + "d".repeat(64);
            assertThatThrownBy(() -> new ImageSignatureVerifier(runner).verify(reference,
                    new PluginSignature(null, null, Files.readString(Path.of(ReferenceSet.root().toString(), "plugins/creates/cosign.pub"))),
                    keys, "1000:1000", "plugin acme-lint", ImageSignatureVerifier.COSIGN)).isInstanceOf(RuntimeException.class);
            // The credentials outlive the run by nothing: the directory written for it is gone.
            try (var left = Files.list(keys)) {
                assertThat(left.map(path -> path.getFileName().toString())).containsExactly("cosign.pub");
            }
            ReferenceSet.expect("plugins/creates/cosign.json", recorded(requests, temporary));
        } finally {
            daemon.stop(0);
        }
    }

    /**
     * A daemon on a loopback port: the images are absent the first time they are inspected — so the
     * pull, and what it sends, is recorded — then present; {@code info} says eight cores.
     */
    private static HttpServer stub(List<Recorded> requests, boolean firstCreateSucceeds) throws IOException {
        java.util.Set<String> pulled = new java.util.HashSet<>();
        int[] creates = {0};
        HttpServer daemon = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        daemon.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath().replaceFirst("^/v[0-9.]+", "");
            String query = exchange.getRequestURI().getRawQuery();
            String method = exchange.getRequestMethod();
            byte[] body = exchange.getRequestBody().readAllBytes();
            byte[] answer = "{}".getBytes(StandardCharsets.UTF_8);
            int status = 200;
            if (path.equals("/info")) {
                answer = "{\"NCPU\":8}".getBytes(StandardCharsets.UTF_8);
            } else if (path.startsWith("/images/") && path.endsWith("/json")) {
                String image = path.substring("/images/".length(), path.length() - "/json".length());
                if (pulled.contains(image)) {
                    answer = "{\"Id\":\"sha256:0\"}".getBytes(StandardCharsets.UTF_8);
                } else {
                    status = 404;
                    answer = "{\"message\":\"No such image\"}".getBytes(StandardCharsets.UTF_8);
                }
            } else if (path.equals("/images/create")) {
                requests.add(new Recorded(method, path + "?" + query, null, exchange.getRequestHeaders().getFirst("X-Registry-Auth")));
                String from = java.net.URLDecoder.decode(query.replaceFirst(".*fromImage=([^&]*).*", "$1"), StandardCharsets.UTF_8);
                String tag = query.contains("tag=") ? java.net.URLDecoder.decode(query.replaceFirst(".*tag=([^&]*).*", "$1"), StandardCharsets.UTF_8) : "";
                pulled.add(tag.isEmpty() ? from : from + (tag.startsWith("sha256:") ? "@" : ":") + tag);
                answer = "{\"status\":\"Status: Downloaded newer image\"}\n".getBytes(StandardCharsets.UTF_8);
            } else if (path.equals("/containers/create")) {
                requests.add(new Recorded(method, path + (query == null ? "" : "?" + query), new String(body, StandardCharsets.UTF_8), null));
                creates[0]++;
                if (firstCreateSucceeds && creates[0] == 1) {
                    status = 201;
                    answer = "{\"Id\":\"holder-id\",\"Warnings\":[]}".getBytes(StandardCharsets.UTF_8);
                } else {
                    status = 500;
                    answer = "{\"message\":\"reference stub: not created\"}".getBytes(StandardCharsets.UTF_8);
                }
            } else if (path.endsWith("/start")) {
                requests.add(new Recorded(method, path, null, null));
                status = 204;
                answer = new byte[0];
            } else if (method.equals("DELETE")) {
                requests.add(new Recorded(method, path + (query == null ? "" : "?" + query), null, null));
                status = 204;
                answer = new byte[0];
            } else {
                status = 404;
                answer = "{\"message\":\"not stubbed\"}".getBytes(StandardCharsets.UTF_8);
            }
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, answer.length == 0 ? -1 : answer.length);
            if (answer.length > 0) {
                exchange.getResponseBody().write(answer);
            }
            exchange.close();
        });
        daemon.start();
        return daemon;
    }

    /** The requests, the temporary paths written as placeholders and every map sorted by key. */
    private static String recorded(List<Recorded> requests, Path temporary) throws Exception {
        List<Object> sorted = new ArrayList<>();
        for (Recorded request : requests) {
            ObjectNode node = NODES.objectNode();
            node.put("method", request.method());
            node.put("path", request.path());
            if (request.body() != null) {
                String body = request.body()
                        .replace(temporary.toRealPath().toString(), "{temporary}")
                        .replace(temporary.toString(), "{temporary}")
                        .replaceAll("registry-login[0-9]+", "registry-login{n}");
                node.set("body", JSON.readTree(body));
            }
            if (request.registryAuth() != null) {
                node.set("registryAuth", JSON.readTree(Base64.getUrlDecoder().decode(request.registryAuth())));
            }
            sorted.add(JSON.treeToValue(node, Object.class));
        }
        return SORTED.writeValueAsString(sorted) + "\n";
    }

    static String lines(ArrayNode answers) throws Exception {
        List<String> each = new ArrayList<>();
        for (JsonNode answer : answers) {
            each.add(JSON.writeValueAsString(answer));
        }
        return "[\n" + String.join(",\n", each) + "\n]\n";
    }
}

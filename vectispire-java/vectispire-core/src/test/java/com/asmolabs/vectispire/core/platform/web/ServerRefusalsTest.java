package com.asmolabs.vectispire.core.platform.web;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireApplication;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.UUID;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.valves.ErrorReportValve;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.tomcat.TomcatWebServer;
import org.springframework.boot.web.server.servlet.context.ServletWebServerApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The refusals made before the application sees a request, through a real Tomcat on a socket.
 *
 * <p><b>Why a socket.</b> MockMvc has no connector, so the refusals under test here do not exist in
 * it: a lone {@code %} is refused by Tomcat's own URI decoding before any filter runs, and Tomcat
 * answered it with its HTML error page. The security firewall's refusals ({@code //}, an encoded
 * {@code ..}) went to the container's error page, which answered a problem's members as {@code
 * application/json}. And no client library sends such a line: a {@code URI} with a lone {@code %}
 * cannot be built, so the request is written by hand.
 */
@SpringBootTest(classes = VectispireApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("apitest")
@DisplayName("the refusals made before the application")
class ServerRefusalsTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @LocalServerPort
    private int port;

    @Autowired
    private ServletWebServerApplicationContext context;

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        Path file = Path.of(System.getProperty("java.io.tmpdir"), "vectispire-servertest-" + UUID.randomUUID() + ".db");
        file.toFile().deleteOnExit();
        registry.add("spring.datasource.url", () -> "jdbc:sqlite:" + file);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"/api/v1//issues", "/api/v1/%2e%2e/issues", "/api/v1/;x/issues"})
    @DisplayName("the firewall's refusal is a problem, as application/problem+json")
    void theFirewall(String target) throws IOException {
        Answer answer = send(target);

        assertThat(answer.status()).isEqualTo(400);
        assertProblem(answer, 400);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"/api/v1/%", "/api/v1/issues%zz", "/%", "/api/v1/issues%2f.."})
    @DisplayName("Tomcat's own refusal of a URI it cannot decode is a problem: no HTML, no server version")
    void theContainer(String target) throws IOException {
        Answer answer = send(target);

        assertThat(answer.status()).isEqualTo(400);
        assertThat(answer.text().toLowerCase(Locale.ROOT)).doesNotContain("<html").doesNotContain("tomcat");
        assertProblem(answer, 400);
    }

    /**
     * One report valve on the host, and it is this one: two are an order question — the one nearer
     * the end reports first — and Tomcat's HTML page would win the day a valve moved.
     */
    @Test
    @DisplayName("the host carries one error report valve, and it is the problem's")
    void oneReportValve() {
        Tomcat tomcat = ((TomcatWebServer) context.getWebServer()).getTomcat();

        assertThat(Arrays.stream(tomcat.getHost().getPipeline().getValves())
                        .filter(valve -> valve instanceof ErrorReportValve))
                .singleElement()
                .isInstanceOf(ProblemErrorReportValve.class);
    }

    private static void assertProblem(Answer answer, int status) throws IOException {
        assertThat(answer.header("content-type")).startsWith("application/problem+json");
        JsonNode problem = JSON.readTree(answer.body());
        assertThat(problem.get("status").asInt()).isEqualTo(status);
        assertThat(problem.path("detail").asText()).as("a sentence the interface can show").isNotBlank();
        assertThat(answer.text()).doesNotContain("Exception").doesNotContain("at org.");
        assertThat(answer.text().toLowerCase(Locale.ROOT)).as("no server version").doesNotContain("tomcat");
    }

    private Answer send(String target) throws IOException {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(("GET " + target + " HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n"
                    + "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
            socket.getOutputStream().flush();
            return Answer.parse(socket.getInputStream().readAllBytes());
        }
    }

    /** A response read off the wire; the body undecoded if it came chunked. */
    private record Answer(int status, String head, String body) {

        static Answer parse(byte[] raw) {
            String all = new String(raw, StandardCharsets.UTF_8);
            int split = all.indexOf("\r\n\r\n");
            String head = split < 0 ? all : all.substring(0, split);
            String body = split < 0 ? "" : all.substring(split + 4);
            if (head.toLowerCase(Locale.ROOT).contains("transfer-encoding: chunked")) {
                body = dechunk(body);
            }
            return new Answer(Integer.parseInt(head.split(" ")[1]), head, body);
        }

        String header(String name) {
            return head.lines()
                    .filter(line -> line.toLowerCase(Locale.ROOT).startsWith(name + ":"))
                    .map(line -> line.substring(name.length() + 1).strip())
                    .findFirst()
                    .orElse("");
        }

        String text() {
            return head + "\n" + body;
        }

        private static String dechunk(String chunked) {
            StringBuilder out = new StringBuilder();
            String rest = chunked;
            while (true) {
                int line = rest.indexOf("\r\n");
                int size = Integer.parseInt(rest.substring(0, line).strip(), 16);
                if (size == 0) {
                    return out.toString();
                }
                out.append(rest, line + 2, line + 2 + size);
                rest = rest.substring(line + 2 + size + 2);
            }
        }
    }
}
